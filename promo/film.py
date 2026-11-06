#!/usr/bin/env python3
"""The whole TrustAuto film: intro.py's opening, then the real CLI, a diagram of where ML decides, and a closing card.

  film.py video ja|en OUT.mp4 [--draft]    picture with captions, silent
  film.py audio OUT.wav                    the same sound for both languages
  film.py frame ja|en T OUT.png            one frame at time T

Every line the terminal shows comes from demo.jsonl, recorded by record.py on a real PTY,
so nothing the program prints is written here. Only the timing is staged: a run takes
what the times below give it, and the character stands in for the cursor while typing.
The ML diagram is drawn, not recorded. It shows the default mode, hybrid, where ML decides
nothing outside allow and envelope; ml mode, which lets it, is a preview the film leaves out.
"""
import json
import math
import subprocess
import sys
from pathlib import Path

from PIL import ImageFont

import intro as o
from intro import ASK, BG, CHIP_SMALL, CHIP_TERM, DENY, FPS, H, INK, MUTED, ROOT, TERM_BAR, TERM_SIZE, TEXT, USER, W

HERE = Path(__file__).resolve().parent
DURATION = 29.9
DEMO = o.DURATION

TERM_BOTTOM = 930
ROW = 50
TYPE_COLOUR = TEXT
COLUMNS = 78  # as recorded, so that apt's own erasing lands where it should

# 256-colour numbers the CLI uses, drawn in the film's own colours.
PALETTE = {16: INK, 215: ROOT, 115: USER, 147: ASK, 210: DENY, 245: MUTED}
BASIC = {32: USER, 33: ROOT}

CAPTIONS = {
    "ja": ["sudo は打っていません", "権限が要らないものは、そのまま", "ルールにないものは、承認を待ちます", "拒否ルールに一致したら、実行しません"],
    "en": ["No sudo typed.", "No privileges needed, none used.", "No matching rule: it waits for approval.", "Matches a deny rule: it never runs."],
}
ML_CAPTION = {
    "ja": "ML が判断するのは、許可した枠の中だけ",
    "en": "ML only decides inside the rules you set.",
}
CLOSING = {
    "ja": ("sudo を打たなくていい。", "ただし、許可した範囲だけ。"),
    "en": ("Stop typing sudo.", "But only for what you allowed."),
}


class Beat:
    def __init__(self, command, start, per_char, out_span, caption, caption_end, face=None, then=None):
        self.command = command
        self.start = start
        self.entered = start + per_char * len(command)
        self.per_char = per_char
        self.out_span = out_span
        self.caption = caption
        self.caption_end = caption_end
        self.face = face
        self.then = then
        self.lines = []
        self.times = []

    @property
    def face_at(self):
        return self.entered + 0.16

    @property
    def output_end(self):
        return self.times[-1] if self.times else self.entered


BEATS = [
    Beat("apt update", 12.30, 0.040, 1.10, 0, 15.10, "root"),
    Beat("apt search '^vim$'", 15.15, 0.026, 0.05, 1, 17.05, None),
    Beat("apt install ./evil.deb", 17.10, 0.030, 0.40, 2, 20.45, "ask", then=19.80),
    Beat("trustauto run -- mkfs -t ext4 /dev/sda", 20.50, 0.026, 0.20, 3, 23.40, "deny"),
]
LEAVE = 23.25
FACE_COLOUR = {"root": ROOT, "ask": ASK, "deny": DENY}
FACE_EYES = {"root": "^^", "ask": "??", "deny": "><"}

# The ML diagram: the terminal becomes the allow/envelope box, the character judges what is
# inside it, and runs into the edge on its way to something outside.
BOX = (460, 240, 1460, 720)
INSIDE = [(620, 420, "root"), (800, 610, "root"), (960, 400, "ask"), (1110, 600, "root"), (1270, 420, "ask")]
OUTSIDE = [(210, 180), (330, 470), (190, 760), (560, 860), (900, 880), (1250, 850), (1700, 800),
           (1640, 470), (1760, 220), (1400, 140), (980, 130), (620, 120)]
VISITS = [LEAVE + 0.75 + 0.24 * k for k in range(len(INSIDE))]
HOP = 0.16
BUMP = VISITS[-1] + 0.14
BUMP_HIT = BUMP + 0.2
OUT = LEAVE + 2.5
CARD = OUT + 0.6
ABOVE = 52


def emulate(text):
    """A small terminal: enough for carriage returns, erasing and colours. Rows of (char, fg, bg)."""
    rows, row, col = [[]], 0, 0
    fg, bg, i = TEXT, None, 0

    def put(ch):
        nonlocal col, row
        if col >= COLUMNS:
            rows.append([])
            row, col = row + 1, 0
        line = rows[row]
        while len(line) <= col:
            line.append((" ", TEXT, None))
        line[col] = (ch, fg, bg)
        col += 1

    while i < len(text):
        ch = text[i]
        if ch == "\x1b" and text[i + 1 : i + 2] == "[":
            j = i + 2
            while not text[j].isalpha():
                j += 1
            params, final = text[i + 2 : j], text[j]
            i = j + 1
            if final == "K":
                del rows[row][col:]
            elif final == "m":
                codes = [int(c) if c else 0 for c in params.split(";")] if not params.startswith("?") else []
                if codes[:2] == [38, 5] and codes[3:5] == [48, 5]:
                    fg, bg = PALETTE[codes[2]], PALETTE[codes[5]]
                elif not codes or codes[0] == 0:
                    fg, bg = TEXT, None
                elif codes[0] in BASIC:
                    fg = BASIC[codes[0]]
            continue
        if ch == "\r":
            col = 0
        elif ch == "\n":
            row += 1
            col = 0
            if row == len(rows):
                rows.append([])
        else:
            put(ch)
        i += 1
    return rows


def plain(row):
    return "".join(c for c, _, _ in row).rstrip()


def load():
    """Finds each beat's output in the recording. A command that was not recorded stops the render."""
    records = [json.loads(line) for line in (HERE / "demo.jsonl").read_text().splitlines()]
    started = [i for i, r in enumerate(records) if r.get("mark") == "start"][0]
    records = records[started + 1 :]
    for beat in BEATS:
        at = [i for i, r in enumerate(records) if r.get("command") == beat.command]
        if not at:
            sys.exit(f"not in the recording: {beat.command}")
        text = ""
        for r in records[at[0] + 1 :]:
            if "command" in r:
                break
            text += r["data"]
        text = text.replace("\x1b[?2004l", "").replace("\x1b[?2004h", "")
        rows = emulate(text)
        # The echo of the typed command is drawn while typing; the prompt follows the output.
        rows = rows[1:]
        while rows and plain(rows[-1]) in ("", "$"):
            rows.pop()
        beat.lines = rows
        first = beat.entered + (0.16 if beat.face else 0.12)
        if beat.then:
            ready = next(i for i, r in enumerate(rows) if plain(r).startswith("Password"))
            beat.times = [mix_time(first, first + beat.out_span, i, ready + 1) for i in range(ready + 1)]
            beat.times += [beat.then] * (len(rows) - ready - 1)
        else:
            beat.times = [mix_time(first, first + beat.out_span, i, len(rows)) for i in range(len(rows))]


def mix_time(a, b, i, n):
    return a if n <= 1 else a + (b - a) * i / (n - 1)


def caption_font(size):
    return ImageFont.truetype(str(HERE / "fonts" / "NotoSansCJKjp-Regular.otf"), size)


def text_origin():
    x0, y0, _, _ = o.terminal_box()
    return x0 + 40, y0 + TERM_BAR + 56


def scrolled(t):
    """Rows on screen at time t, as (cells, prompt text or None), oldest first."""
    rows, typing = [], None
    for beat in BEATS:
        if t < beat.start:
            typing = typing or ("", 0)
            break
        shown = int((t - beat.start) / beat.per_char)
        if shown < len(beat.command):
            rows.append(("$ " + beat.command[:shown], None))
            typing = ("cursor", 2 + shown)
            return rows, typing
        rows.append(("$ " + beat.command, None))
        lines = [row for row, when in zip(beat.lines, beat.times) if t >= when]
        rows.extend((None, row) for row in lines)
        if len(lines) < len(beat.lines):
            return rows, ("busy", 0)
    rows.append(("$ ", None))
    return rows, ("cursor", 2)


def draw_row(c, x, y, row, cell, fade):
    i = 0
    while i < len(row):
        ch, fg, bg = row[i]
        if bg is not None:
            j = i
            while j < len(row) and row[j][2] == bg:
                j += 1
            width = (j - i) * cell
            c.rect(x + i * cell + width / 2, y, width, ROW - 8, o.blend(o.PANEL, bg, fade), radius=5)
            for k in range(i, j):
                if row[k][0] != " ":
                    c.text(x + k * cell + cell / 2, y, row[k][0], TERM_SIZE, o.blend(o.PANEL, row[k][1], fade), "mm", bold=True)
            i = j
            continue
        if ch != " ":
            c.text(x + i * cell, y, ch, TERM_SIZE, o.blend(o.PANEL, fg, fade))
        i += 1


def terminal_shell(c, fade, t):
    x0, y0, x1, y1 = o.terminal_box()
    s = c.s
    # The window makes room for captions as the demo starts.
    bottom = o.mix(y1, TERM_BOTTOM, o.ease_in_out(o.span(t, DEMO, DEMO + 0.25)))
    c.draw.rounded_rectangle(
        [x0 * s, y0 * s, x1 * s, bottom * s], 14 * s, fill=o.blend(BG, o.PANEL, fade), outline=o.blend(BG, o.LINE, fade), width=2 * s
    )
    c.draw.rounded_rectangle([(x0 + 1) * s, (y0 + 1) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], 13 * s, fill=o.blend(BG, o.PANEL_BAR, fade))
    c.draw.rectangle([(x0 + 1) * s, (y0 + TERM_BAR - 14) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], fill=o.blend(BG, o.PANEL_BAR, fade))
    c.text(x0 + 24, y0 + TERM_BAR / 2, "bash", 24, o.blend(BG, MUTED, fade))


def chip_cursor(c, x, y, cell, t):
    eyes = "00"
    # The character blinks now and then while it waits.
    if (t * 0.9) % 1 < 0.05:
        eyes = "--"
    c.chip(x + CHIP_TERM[0] / 2, y, CHIP_TERM, ROOT, eyes)


def draw_demo(c, t):
    # The window itself is the diagram's box from LEAVE on; only the text fades here.
    fade = 1 - o.span(t, LEAVE, LEAVE + 0.2)
    if fade <= 0:
        return
    if t < LEAVE:
        terminal_shell(c, fade, t)
    x, top = text_origin()
    cell = o.font(TERM_SIZE).getlength("0")
    rows, typing = scrolled(t)
    visible = int((TERM_BOTTOM - top) // ROW)
    first = max(0, len(rows) - visible)
    for i, (typed, cells) in enumerate(rows[first:]):
        y = top + i * ROW
        if typed is not None:
            c.text(x, y, "$", TERM_SIZE, o.blend(BG, MUTED, fade))
            if len(typed) > 2:
                c.text(x + cell * 2, y, typed[2:], TERM_SIZE, o.blend(BG, TEXT, fade))
        else:
            draw_row(c, x, y, cells, cell, fade)
    if typing[0] == "cursor" and fade == 1:
        y = top + (len(rows) - first - 1) * ROW
        chip_cursor(c, x + cell * typing[1], y, cell, t)


def draw_caption(c, t, language):
    for beat in BEATS:
        on = beat.entered + 0.1
        if on <= t < beat.caption_end:
            fade = o.span(t, on, on + 0.18) * (1 - o.span(t, beat.caption_end - 0.2, beat.caption_end))
            text = CAPTIONS[language][beat.caption]
            colour = o.blend(BG, TEXT, fade)
            c.draw.text((W / 2 * c.s, 1005 * c.s), text, font=caption_font(46 * c.s), fill=colour, anchor="mm")
    on, off = LEAVE + 0.55, OUT + 0.2
    if on <= t < off:
        fade = o.span(t, on, on + 0.18) * (1 - o.span(t, off - 0.2, off))
        c.draw.text((W / 2 * c.s, 1005 * c.s), ML_CAPTION[language], font=caption_font(46 * c.s), fill=o.blend(BG, TEXT, fade), anchor="mm")


def cursor_at_leave():
    x0, top = text_origin()
    cell = o.font(TERM_SIZE).getlength("0")
    rows, _ = scrolled(LEAVE - 0.01)
    visible = int((TERM_BOTTOM - top) // ROW)
    return x0 + cell * 2 + CHIP_TERM[0] / 2, top + (min(len(rows), visible) - 1) * ROW


def ml_character(t):
    """Where the character is in the diagram, and how it looks: (x, y, geometry, colour, eyes)."""
    w, h, size, gap = CHIP_TERM
    spots = [(x, y - ABOVE) for x, y, _ in INSIDE]
    if t < VISITS[0]:
        # Out of the prompt and onto the first command, the way it jumped in.
        sx, sy = cursor_at_leave()
        p = o.ease_in_out(o.span(t, LEAVE + 0.15, VISITS[0]))
        x, y = o.mix(sx, spots[0][0], p), o.mix(sy, spots[0][1], p) - math.sin(p * math.pi) * 90
        return x, y, CHIP_TERM, ROOT, "^^" if 0 < p < 1 else "00"
    if t < BUMP:
        k = max(i for i, v in enumerate(VISITS) if t >= v)
        leave = VISITS[k + 1] - HOP if k + 1 < len(VISITS) else BUMP
        if t < leave:
            hop = 1 - o.span(t, VISITS[k], VISITS[k] + 0.14)
            grow = 1 + 0.16 * hop * hop
            face = INSIDE[k][2]
            x, y = spots[k]
            return x, y - 14 * hop * hop, (w * grow, h * grow, size * grow, gap * grow), FACE_COLOUR[face], FACE_EYES[face]
        p = o.ease_in_out(o.span(t, leave, VISITS[k + 1]))
        (ax, ay), (bx, by) = spots[k], spots[k + 1]
        return o.mix(ax, bx, p), o.mix(ay, by, p) - math.sin(p * math.pi) * 34, CHIP_TERM, ROOT, "00"
    # Towards something outside the box, which it cannot reach.
    target_y = OUTSIDE[7][1]
    wall = BOX[2] - w / 2 - 4
    ax, ay = spots[-1]
    if t < BUMP_HIT:
        p = o.span(t, BUMP, BUMP_HIT) ** 2
        return o.mix(ax, wall, p), o.mix(ay, target_y, p), CHIP_TERM, ROOT, "00"
    back = o.ease_out(o.span(t, BUMP_HIT, BUMP_HIT + 0.22))
    squash = 0.2 * (1 - o.span(t, BUMP_HIT, BUMP_HIT + 0.18)) ** 2
    eyes = "><" if t < BUMP_HIT + 0.38 else "00"
    x = wall - 30 * back + w * squash / 2
    return x, target_y, (w * (1 - squash), h * (1 + squash), size, gap * (1 - squash)), ROOT, eyes


def draw_ml(c, t, language):
    if t < LEAVE or t >= CARD:
        return
    s = c.s
    out = 1 - o.span(t, OUT - 0.05, OUT + 0.4)

    # The terminal window shrinks into the box that the rules draw.
    m = o.ease_in_out(o.span(t, LEAVE + 0.05, LEAVE + 0.6))
    tx0, ty0, tx1, _ = o.terminal_box()
    x0, y0, x1, y1 = (o.mix(a, b, m) for a, b in zip((tx0, ty0, tx1, TERM_BOTTOM), BOX))
    edge = o.blend(o.LINE, MUTED, m)
    c.draw.rounded_rectangle(
        [x0 * s, y0 * s, x1 * s, y1 * s], 14 * s, fill=o.blend(BG, o.PANEL, (1 - m * 0.6) * out), outline=o.blend(BG, edge, out), width=round(o.mix(2, 3, m) * s)
    )
    if m < 1:
        bar = o.blend(o.blend(BG, o.PANEL, 1 - m * 0.6), o.PANEL_BAR, 1 - m)
        c.draw.rounded_rectangle([(x0 + 1) * s, (y0 + 1) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], 13 * s, fill=bar)
        c.draw.rectangle([(x0 + 1) * s, (y0 + TERM_BAR - 14) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], fill=bar)
        c.text(x0 + 24, y0 + TERM_BAR / 2, "bash", 24, o.blend(BG, MUTED, 1 - o.span(m, 0, 0.5)))
    label = o.span(t, LEAVE + 0.45, LEAVE + 0.75) * out
    if label > 0:
        c.text(x0 + 28, y0 + 34, "allow / envelope", 26, o.blend(BG, MUTED, label))

    # Commands. Those outside the box never change; those inside take the colour of the decision.
    for i, (x, y) in enumerate(OUTSIDE):
        pop = o.clamp(o.spring(o.span(t, LEAVE + 0.4 + i * 0.02, LEAVE + 0.52 + i * 0.02)), 0, 1.06)
        if pop > 0:
            c.rect(x, y, 22 * pop, 22 * pop, o.blend(BG, o.blend(BG, MUTED, 0.4), out), radius=5)
    for i, (x, y, face) in enumerate(INSIDE):
        pop = o.clamp(o.spring(o.span(t, LEAVE + 0.5 + i * 0.03, LEAVE + 0.62 + i * 0.03)), 0, 1.06)
        if pop <= 0:
            continue
        colour = o.blend(BG, TEXT, 0.55)
        if t >= VISITS[i]:
            colour = FACE_COLOUR[face]
            pop *= 1 + 0.4 * (1 - o.span(t, VISITS[i], VISITS[i] + 0.15)) ** 2
        c.rect(x, y, 22 * pop, 22 * pop, o.blend(BG, colour, out), radius=5)

    if t < OUT:
        x, y, geometry, colour, eyes = ml_character(t)
        c.chip(x, y, geometry, colour, eyes)


def draw_closing(c, t, language):
    if t < OUT:
        return
    # The character leaves the diagram the way it came into the terminal.
    move = o.ease_in_out(o.span(t, OUT, CARD))
    start_x, start_y, _, _, _ = ml_character(OUT - 0.001)
    cy_final = H / 2 - 150
    cx = o.mix(start_x, W / 2, move)
    cy = o.mix(start_y, cy_final, move) - math.sin(move * math.pi) * 70
    grow = o.span(t, OUT + 0.1, CARD)
    geometry = tuple(o.geo(a, b, o.ease_in_out(grow)) for a, b in zip(CHIP_TERM, CHIP_SMALL))
    eyes = "^^" if t < CARD + 0.1 else "00"
    if CARD + 2.3 <= t < CARD + 2.42:
        eyes = "--"
    c.chip(cx, cy, geometry, ROOT, eyes)

    one, two = CLOSING[language]
    a = o.span(t, CARD + 0.1, CARD + 0.5)
    b = o.span(t, CARD + 0.55, CARD + 0.95)
    n = o.span(t, CARD + 1.15, CARD + 1.55)
    size = 66 if language == "ja" else 62
    if a > 0:
        c.draw.text((W / 2 * c.s, (H / 2 - 20) * c.s), one, font=caption_font(size * c.s), fill=o.blend(BG, TEXT, a), anchor="mm")
    if b > 0:
        c.draw.text((W / 2 * c.s, (H / 2 + 72) * c.s), two, font=caption_font(size * c.s), fill=o.blend(BG, MUTED, b), anchor="mm")
    if n > 0:
        c.text(W / 2, H / 2 + 200, "TrustAuto v1.0.0-preview.1", 40, o.blend(BG, TEXT, n), "mm")


def render(t, language, scale=2):
    if t < DEMO:
        return o.render(t, scale)
    c = o.Canvas(scale)
    # The box is the terminal window, so the last of the terminal's text goes on top of it.
    draw_ml(c, t, language)
    draw_demo(c, t)
    draw_caption(c, t, language)
    draw_closing(c, t, language)
    return c.image.reduce(scale) if scale > 1 else c.image


def write_video(language, path, draft):
    scale, fps = (1, 30) if draft else (2, FPS)
    encoder = subprocess.Popen(
        ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(fps), "-i", "-",
         "-c:v", "libx264", "-preset", "medium", "-crf", "14", "-pix_fmt", "yuv420p", path],
        stdin=subprocess.PIPE,
    )
    for i in range(int(DURATION * fps)):
        encoder.stdin.write(render(i / fps, language, scale).tobytes())
    encoder.stdin.close()
    if encoder.wait() != 0:
        sys.exit("ffmpeg failed")


def demo_sound(m):
    # Notes are the ones the opening gives each expression.
    note = {"root": (523.25, 1.1), "ask": (783.99, 1.12), "deny": (311.13, 0.82)}
    for beat in BEATS:
        for i in range(len(beat.command)):
            m.tick(beat.start + beat.per_char * i, 0.13, pan=-0.3 + 0.5 * i / len(beat.command))
        m.tick(beat.entered, 0.24)
        if beat.face:
            f, up = note[beat.face]
            m.blip(beat.face_at, f, 0.26, up=up)
        if beat.then:
            m.tick(beat.then, 0.2)
    # Output arriving, kept under everything else.
    apt = BEATS[0]
    for when in apt.times:
        m.tick(when, 0.05, pan=0.2)

    # The window shrinks into the box, and the commands appear around it.
    m.add(LEAVE, m.sweep_noise(0.6, 3600, 700), 0.4, send=0.3)
    m.add(LEAVE + 0.05, m.glide(420, 150, 0.55, 2.5, (1.0, 0.2)), 0.18, send=0.3)
    for i in range(len(OUTSIDE)):
        m.tick(LEAVE + 0.4 + i * 0.02, 0.08, pan=-0.6 + 1.2 * i / len(OUTSIDE))
    m.add(LEAVE + 0.15, m.glide(240, 780, 0.22, 2.2, (1.0, 0.2)), 0.22, send=0.35)

    # One decision per command inside, with the notes of the opening; then the edge.
    note = {"root": (523.25, 1.1), "ask": (783.99, 1.12)}
    for (x, _, face), when in zip(INSIDE, VISITS):
        f, up = note[face]
        m.blip(when, f, 0.22, pan=(x - W / 2) / W, up=up)
    m.add(BUMP_HIT, m.glide(150, 72, 0.14, 8), 0.7, 0.3, send=0.15)
    m.add(BUMP_HIT, m.noise(0.03, 900, 5000, 8), 0.4, 0.3, send=0.15)
    m.blip(BUMP_HIT + 0.04, 311.13, 0.16, 0.3, up=0.82)

    # The character leaves, and the closing card settles.
    m.add(OUT, m.glide(240, 780, 0.22, 2.2, (1.0, 0.2)), 0.26, send=0.35)
    m.add(CARD, m.glide(150, 62, 1.2, 3), 0.65, send=0.3)
    m.click(CARD, 0.3)
    m.drone(CARD, DURATION - CARD - 0.2, (220.0, 329.63, 440.0, 659.25), 0.05)
    m.tick(CARD + 2.3, 0.18)
    m.tick(CARD + 2.42, 0.12)


def write_audio(path):
    m = o.Mix(DURATION + 0.4)
    o.opening(m)
    demo_sound(m)
    o.write_audio(path, o.finish(m))


def main():
    load()
    kind = sys.argv[1]
    if kind == "video":
        write_video(sys.argv[2], sys.argv[3], "--draft" in sys.argv)
    elif kind == "audio":
        write_audio(sys.argv[2])
    elif kind == "frame":
        render(float(sys.argv[3]), sys.argv[2]).save(sys.argv[4])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
