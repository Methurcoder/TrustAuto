#!/usr/bin/env python3
"""Opening of the TrustAuto film: the character, the title, and its way back into the CLI.

  intro.py video OUT.mp4 [--draft]    frames piped into ffmpeg, silent
  intro.py audio OUT.wav              synthesised sound, nothing sampled
  intro.py frame T OUT.png            one frame at time T

Picture and sound read the same times below, so they cannot drift apart.
"""
import math
import random
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from scipy.signal import butter, fftconvolve, lfilter

HERE = Path(__file__).resolve().parent
W, H = 1920, 1080
FPS = 60
DURATION = 12.2

BG = (13, 15, 14)
PANEL = (20, 23, 21)
PANEL_BAR = (26, 30, 27)
LINE = (42, 47, 43)
TEXT = (221, 225, 218)
MUTED = (152, 160, 150)
ROOT = (240, 180, 74)
USER = (132, 197, 166)
ASK = (169, 182, 245)
DENY = (242, 131, 123)
INK = (13, 15, 14)

# The times every scene and sound hang on.
BLINK_1 = 0.75
SPREAD = 1.40
WINK = 1.65
WINK_END = 2.05
BLINK_2 = 2.50
SHRINK = 2.90
SHRUNK = 3.35
EXPRESSIONS = [
    (3.35, ROOT, "00"),
    (3.75, ROOT, "^^"),
    (4.05, USER, "00"),
    (4.35, ASK, "??"),
    (4.65, DENY, "><"),
    (4.95, ROOT, "--"),
    (5.20, ROOT, "00"),
]
BURST = 5.42
LOCK = 6.45
VERSION_END = 6.95
BRACKETS = 6.95
PREVIEW_START = 7.08
PREVIEW_END = 7.60
TITLE_SHRINK = 8.10
TITLE_SMALL = 8.55
DROP_NAME = 8.95
DROP_VERSION = 9.45
CLOSE = 9.95
DOT = 10.18
DOT_BEEPS = [(10.25, ROOT), (10.50, USER), (10.75, ASK)]
WAKE = 10.95
LAND = 11.40
BLINK_3 = 11.78

TITLE = "TrustAuto v1.0.0[Preview]"
TITLE_SIZE = 96
TERM_SIZE = 35
TERM_MARGIN = 96
TERM_BAR = 56
CHIP_SMALL = (230, 102, 74, 82)  # width, height, eye size, gap between eyes
CHIP_TERM = (105, 46, 33, 35)


def font(size, bold=False):
    name = "IBMPlexMono-Bold.ttf" if bold else "IBMPlexMono-Regular.ttf"
    return ImageFont.truetype(str(HERE / "fonts" / name), size)


def clamp(x, a=0.0, b=1.0):
    return max(a, min(b, x))


def span(t, a, b):
    return clamp((t - a) / (b - a))


def ease_out(x):
    return 1 - (1 - x) ** 3


def ease_in_out(x):
    return 4 * x * x * x if x < 0.5 else 1 - (-2 * x + 2) ** 3 / 2


def spring(x):
    """Settles at 1 with one overshoot."""
    return 1 - math.exp(-6 * x) * math.cos(9 * x)


def mix(a, b, x):
    return a + (b - a) * x


def geo(a, b, x):
    return math.exp(mix(math.log(a), math.log(b), x))


def blend(c1, c2, x):
    return tuple(int(round(mix(p, q, x))) for p, q in zip(c1, c2))


def title_layout():
    f = font(TITLE_SIZE)
    cell = f.getlength("0")
    return cell, (W - cell * len(TITLE)) / 2


def particle_set():
    """Cells of the word TrustAuto, drawn from the chip to their places."""
    cell, left = title_layout()
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).text((left, H / 2), "TrustAuto", font=font(TITLE_SIZE), fill=255, anchor="lm")
    pixels = np.asarray(mask)
    step = 4
    rng = random.Random(4)
    out = []
    for y in range(0, H, step):
        for x in range(0, W, step):
            if pixels[y, x] > 110:
                angle = rng.uniform(0, math.tau)
                out.append(
                    (
                        x + step / 2,
                        y + step / 2,
                        rng.uniform(0, 0.32),
                        rng.uniform(0.42, 0.62),
                        math.cos(angle) * rng.uniform(120, 620),
                        math.sin(angle) * rng.uniform(80, 340),
                    )
                )
    return out


PARTICLES = particle_set()


class Canvas:
    def __init__(self, scale):
        self.s = scale
        self.image = Image.new("RGB", (W * scale, H * scale), BG)
        self.draw = ImageDraw.Draw(self.image)

    def rect(self, cx, cy, w, h, colour, radius=0):
        s = self.s
        box = [(cx - w / 2) * s, (cy - h / 2) * s, (cx + w / 2) * s, (cy + h / 2) * s]
        if radius > 0:
            self.draw.rounded_rectangle(box, radius * s, fill=colour)
        else:
            self.draw.rectangle(box, fill=colour)

    def text(self, x, y, text, size, colour, anchor="lm", bold=False):
        self.draw.text((x * self.s, y * self.s), text, font=font(size * self.s, bold), fill=colour, anchor=anchor)

    def chip(self, cx, cy, geometry, colour, eyes, tilt=0.0):
        w, h, size, gap = geometry
        self.rect(cx, cy, w, h, colour, radius=min(w, h) * 0.12)
        self.text(cx - gap / 2, cy - tilt, eyes[0], size, INK, "mm", bold=True)
        self.text(cx + gap / 2, cy + tilt, eyes[1], size, INK, "mm", bold=True)


def full_face(t):
    """Eyes and spacing while the character fills the screen."""
    eyes = "00"
    if BLINK_1 <= t < BLINK_1 + 0.12 or BLINK_2 <= t < BLINK_2 + 0.12:
        eyes = "--"
    if WINK <= t < WINK_END:
        eyes = "0<"
    spread = mix(1.0, 1.26, ease_out(span(t, SPREAD, SPREAD + 0.22)))
    size = geo(760, 620, ease_out(span(t, 0, 0.35)))
    return eyes, (W * 1.05, H * 1.05, size, 760 * spread)


def draw_character(c, t):
    if t < SHRINK:
        eyes, geometry = full_face(t)
        tilt = 26 if WINK <= t < WINK_END else 0
        c.chip(W / 2, H / 2, geometry, ROOT, eyes, tilt)
        return
    if t < SHRUNK:
        _, big = full_face(SHRINK - 0.01)
        x = span(t, SHRINK, SHRUNK)
        p = clamp(spring(x), 0, 1.06)
        # Geometric steps read as the same object moving away.
        geometry = tuple(geo(a, b, min(p, 1.0)) for a, b in zip(big, CHIP_SMALL))
        if p > 1:
            geometry = tuple(v * (1 - (p - 1)) for v in CHIP_SMALL)
        c.chip(W / 2, H / 2, geometry, ROOT, "00")
        return
    current = EXPRESSIONS[0]
    for item in EXPRESSIONS:
        if t >= item[0]:
            current = item
    hop = 1 - span(t, current[0], current[0] + 0.14)
    grow = 1 + 0.16 * hop * hop
    w, h, size, gap = CHIP_SMALL
    if t > BURST - 0.1:
        grow *= 1 + 0.25 * span(t, BURST - 0.1, BURST)
    c.chip(
        W / 2,
        H / 2 - 14 * hop * hop,
        (w * grow, h * grow, size * grow, gap * grow),
        current[1],
        current[2],
    )


def draw_particles(c, t):
    fade = 1 - span(t, LOCK - 0.05, LOCK + 0.14)
    if fade <= 0:
        return
    for x, y, delay, length, dx, dy in PARTICLES:
        p = span(t, BURST + delay, BURST + delay + length)
        if t < BURST + delay:
            continue
        mid = math.sin(p * math.pi)
        px = mix(W / 2, x, ease_in_out(p)) + dx * mid
        py = mix(H / 2, y, ease_in_out(p)) + dy * mid
        colour = blend(BG, blend(ROOT, TEXT, span(p, 0.7, 1.0)), fade)
        size = mix(9, 4.4, ease_in_out(p))
        c.rect(px, py, size, size, colour)


SCRAMBLE = "01#$<>^?*/\\|"


def decoded(text, start, end, t):
    """How much of a word has appeared, and noise for the character being written."""
    if t < start:
        return ""
    if t >= end:
        return text
    done = int((t - start) / (end - start) * len(text))
    noise = random.Random(int(t * 24) + len(text))
    return text[:done] + noise.choice(SCRAMBLE)


def title_parts(t):
    """Words as (text, colour, index in the title); index stays fixed so nothing jumps."""
    parts = []
    name_on = t >= LOCK - 0.05
    if name_on and t < DROP_NAME:
        parts.append(("TrustAuto", blend(BG, TEXT, span(t, LOCK - 0.05, LOCK + 0.1)), 0))
    if t < DROP_VERSION:
        parts.append((decoded("v1.0.0", LOCK, VERSION_END, t), USER, 10))
    if t >= BRACKETS and t < DOT:
        parts.append((decoded("Preview", PREVIEW_START, PREVIEW_END, t), ASK, 17))
    return parts


def draw_title(c, t):
    if t < LOCK - 0.05 or t >= DOT:
        return
    scale = geo(1.0, 0.5, ease_in_out(span(t, TITLE_SHRINK, TITLE_SMALL)))
    cell = font(TITLE_SIZE).getlength("0")

    # The centre follows what is left of the title.
    def centre_of(first, last):
        return (first + last) / 2

    centre = centre_of(0, 25)
    if t >= DROP_NAME:
        centre = mix(centre, centre_of(10, 25), ease_out(span(t, DROP_NAME, DROP_NAME + 0.2)))
    if t >= DROP_VERSION:
        centre = mix(centre, centre_of(16, 25), ease_out(span(t, DROP_VERSION, DROP_VERSION + 0.2)))

    def x_of(index):
        return W / 2 + (index - centre) * cell * scale

    size = TITLE_SIZE * scale
    closing = span(t, CLOSE, DOT)
    head = None
    for text, colour, index in title_parts(t):
        if index == 17 and closing > 0:
            # Letters leave from both ends as the brackets close in.
            keep = int(round(len(text) * (1 - closing)))
            cut = (len(text) - keep) // 2
            text = text[cut:cut + keep]
            index = 20.5 - len(text) / 2
        if index == 17 and t < CLOSE and len(text) < 7:
            head = index + len(text)
        if index == 10 and t < VERSION_END:
            head = index + len(text)
        if text:
            c.text(x_of(index), H / 2, text, size, colour)
    if BRACKETS <= t:
        pop = spring(span(t, BRACKETS, BRACKETS + 0.14))
        gap = mix(4.5, 1.0, ease_in_out(closing)) * pop
        for ch, index in (("[", 20.5 - gap), ("]", 20.5 + gap - 1)):
            c.text(x_of(index), H / 2, ch, size, TEXT)
    if head is not None:
        c.rect(x_of(head) + cell * scale / 2, H / 2, cell * scale, size * 1.18, ROOT)


def terminal_box():
    return TERM_MARGIN, TERM_MARGIN * 0.6, W - TERM_MARGIN, H - TERM_MARGIN * 0.6


def prompt_position():
    x0, y0, _, _ = terminal_box()
    cell = font(TERM_SIZE).getlength("0")
    return x0 + 40, y0 + TERM_BAR + 56, cell


def draw_terminal(c, t):
    fade = ease_out(span(t, WAKE, WAKE + 0.45))
    if fade <= 0:
        return
    x0, y0, x1, y1 = terminal_box()
    s = c.s
    c.draw.rounded_rectangle(
        [x0 * s, y0 * s, x1 * s, y1 * s], 14 * s, fill=blend(BG, PANEL, fade), outline=blend(BG, LINE, fade), width=2 * s
    )
    c.draw.rounded_rectangle(
        [(x0 + 1) * s, (y0 + 1) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], 13 * s, fill=blend(BG, PANEL_BAR, fade)
    )
    c.draw.rectangle([(x0 + 1) * s, (y0 + TERM_BAR - 14) * s, (x1 - 1) * s, (y0 + TERM_BAR) * s], fill=blend(BG, PANEL_BAR, fade))
    c.text(x0 + 24, y0 + TERM_BAR / 2, "bash", 24, blend(BG, MUTED, fade))
    px, py, cell = prompt_position()
    c.text(px, py, "$", TERM_SIZE, blend(BG, MUTED, fade))


def draw_dot_and_return(c, t):
    if t < DOT:
        return
    if t < WAKE:
        colour = TEXT
        for start, beep in DOT_BEEPS:
            if t >= start:
                colour = beep
        pulse = 0.0
        for start, _ in DOT_BEEPS:
            if t >= start:
                pulse = max(pulse, 1 - span(t, start, start + 0.16))
        appear = spring(span(t, DOT, DOT + 0.1))
        r = (11 + 6 * pulse) * appear
        c.draw.ellipse([(W / 2 - r) * c.s, (H / 2 - r) * c.s, (W / 2 + r) * c.s, (H / 2 + r) * c.s], fill=colour)
        return
    px, py, cell = prompt_position()
    target_x = px + cell * 2 + CHIP_TERM[0] / 2
    x = span(t, WAKE, LAND)
    move = ease_in_out(x)
    cx = mix(W / 2, target_x, move)
    # A small jump, higher than a straight line to the prompt.
    cy = mix(H / 2, py, move) - math.sin(move * math.pi) * 90
    open_up = max(0.05, spring(span(t, WAKE, WAKE + 0.22)))
    bounce = 1 - span(t, LAND, LAND + 0.2)
    squash = 0.16 * bounce * bounce
    w, h, size, gap = CHIP_TERM
    geometry = ((w * (1 + squash)) * open_up, h * (1 - squash) * open_up, size * open_up, gap * open_up)
    eyes = "00"
    if BLINK_3 <= t < BLINK_3 + 0.12:
        eyes = "--"
    if WAKE <= t < LAND:
        eyes = "^^"
    c.chip(cx, cy + h * squash / 2, geometry, ROOT, eyes)


def render(t, scale=2):
    c = Canvas(scale)
    if t < BURST:
        draw_character(c, t)
    else:
        draw_terminal(c, t)
        draw_particles(c, t)
        draw_title(c, t)
        draw_dot_and_return(c, t)
    return c.image.reduce(scale) if scale > 1 else c.image


def write_video(path, draft):
    scale, fps = (1, 30) if draft else (2, FPS)
    encoder = subprocess.Popen(
        ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(fps), "-i", "-",
         "-c:v", "libx264", "-preset", "medium", "-crf", "12", "-pix_fmt", "yuv420p", path],
        stdin=subprocess.PIPE,
    )
    for i in range(int(DURATION * fps)):
        encoder.stdin.write(render(i / fps, scale).tobytes())
    encoder.stdin.close()
    if encoder.wait() != 0:
        sys.exit("ffmpeg failed")


# Sound. Every event is synthesised here; no recording or sample is used.
SR = 48000


class Mix:
    def __init__(self, seconds):
        self.dry = np.zeros((int(seconds * SR), 2))
        self.wet = np.zeros_like(self.dry)
        self.rng = np.random.default_rng(11)

    def add(self, t, signal, gain=1.0, pan=0.0, send=0.2):
        start = int(t * SR)
        end = min(start + len(signal), len(self.dry))
        part = signal[: end - start] * gain
        left, right = math.cos((pan + 1) * math.pi / 4), math.sin((pan + 1) * math.pi / 4)
        self.dry[start:end, 0] += part * left
        self.dry[start:end, 1] += part * right
        self.wet[start:end, 0] += part * left * send
        self.wet[start:end, 1] += part * right * send

    def glide(self, f0, f1, seconds, decay=None, harmonics=(1.0,)):
        n = int(seconds * SR)
        x = np.linspace(0, 1, n, endpoint=False)
        phase = 2 * np.pi * np.cumsum(f0 * (f1 / f0) ** x) / SR
        wave = sum(a * np.sin(phase * (i + 1)) for i, a in enumerate(harmonics))
        envelope = np.exp(-x * (decay if decay else 5.0)) * np.minimum(1, x * seconds / 0.004)
        return wave * envelope

    def noise(self, seconds, low, high, decay=8.0):
        n = int(seconds * SR)
        b, a = butter(2, [low / (SR / 2), high / (SR / 2)], "band")
        x = np.linspace(0, 1, n, endpoint=False)
        return lfilter(b, a, self.rng.standard_normal(n)) * np.exp(-x * decay) * np.minimum(1, x * seconds / 0.002)

    def sweep_noise(self, seconds, f0, f1, shape_up=True):
        """Noise through a moving band, in short overlapping pieces."""
        n = int(seconds * SR)
        out = np.zeros(n)
        hop = 512
        size = 2048
        window = np.hanning(size)
        for i in range(0, max(1, n - size), hop):
            x = i / max(1, n - size)
            f = f0 * (f1 / f0) ** x
            b, a = butter(2, [max(30, f * 0.7) / (SR / 2), min(SR / 2 - 100, f * 1.4) / (SR / 2)], "band")
            out[i:i + size] += lfilter(b, a, self.rng.standard_normal(size)) * window
        x = np.linspace(0, 1, n)
        envelope = np.sin(x * np.pi) ** 1.5
        return out * envelope * 0.35

    def click(self, t, gain=1.0, pan=0.0):
        self.add(t, self.noise(0.018, 1800, 9000, 9), gain * 0.5, pan, send=0.5)
        self.add(t, self.glide(240, 110, 0.07, 6), gain * 0.9, pan, send=0.4)

    def tick(self, t, gain=0.2, pan=0.0):
        self.add(t, self.noise(0.012, 2500, 11000, 8), gain, pan, send=0.15)

    def blip(self, t, f, gain=0.3, pan=0.0, seconds=0.16, up=1.04):
        self.add(t, self.glide(f, f * up, seconds, 7, (1.0, 0.28, 0.08)), gain, pan, send=0.35)

    def drone(self, t, seconds, freqs, gain):
        n = int(seconds * SR)
        x = np.linspace(0, 1, n, endpoint=False)
        tt = np.arange(n) / SR
        wave = sum(np.sin(2 * np.pi * f * tt + i) * (1 + 0.2 * np.sin(2 * np.pi * (0.7 + i * 0.3) * tt)) for i, f in enumerate(freqs))
        self.add(t, wave * np.minimum(1, x * 18) * (1 - x) ** 1.6, gain, 0.0, send=0.25)


def opening(m):
    # Filling the screen.
    m.add(0.0, m.glide(95, 42, 1.1, 4), 0.85, send=0.3)
    m.tick(BLINK_1, 0.28)
    m.tick(BLINK_1 + 0.12, 0.18)
    m.add(SPREAD, m.glide(150, 300, 0.2, 3, (1.0, 0.3)), 0.3, send=0.3)
    m.add(WINK, m.glide(420, 880, 0.18, 4, (1.0, 0.2)), 0.34, 0.35, send=0.45)
    m.add(WINK_END, m.glide(620, 500, 0.08, 5), 0.16, 0.35)
    m.tick(BLINK_2, 0.28)
    m.tick(BLINK_2 + 0.12, 0.18)

    # Shrinking to the size of a terminal row.
    m.add(SHRINK, m.sweep_noise(SHRUNK - SHRINK + 0.05, 5200, 500), 0.6, send=0.3)
    m.add(SHRINK, m.glide(760, 130, SHRUNK - SHRINK, 1.5, (1.0, 0.2)), 0.3, send=0.3)
    m.add(SHRUNK, m.glide(120, 58, 0.26, 7), 0.8, send=0.3)
    m.click(SHRUNK, 0.5)

    # One note per expression. Refused is the only falling one.
    notes = {3.75: (523.25, 1.1), 4.05: (659.25, 1.03), 4.35: (783.99, 1.12), 4.65: (311.13, 0.82), 4.95: (392.0, 0.97), 5.20: (523.25, 1.02)}
    for i, (t, (f, up)) in enumerate(notes.items()):
        m.blip(t, f, 0.3, pan=(-1) ** i * 0.15, up=up)

    # Burst, the cells arriving, the word locking in.
    m.add(BURST, m.noise(0.25, 500, 6000, 7), 0.5, send=0.5)
    m.add(BURST, m.glide(180, 70, 0.3, 5), 0.6, send=0.3)
    m.add(BURST + 0.1, m.sweep_noise(LOCK - BURST - 0.1, 400, 6500), 0.34, send=0.3)
    grains = random.Random(9)
    for _ in range(90):
        x = grains.random() ** 0.6
        t = BURST + 0.08 + x * (LOCK - BURST - 0.1)
        m.add(t, m.glide(mix(500, 2200, x) * grains.uniform(0.92, 1.08), mix(520, 2300, x), 0.035, 6), 0.07, grains.uniform(-0.8, 0.8), send=0.4)
    m.add(LOCK, m.glide(82, 38, 2.3, 2.6), 1.0, send=0.25)
    m.click(LOCK, 0.4)
    m.drone(LOCK, TITLE_SMALL + 0.3 - LOCK, (220.0, 329.63, 440.0, 659.25, 880.0), 0.05)

    # Characters being written.
    for text, start, end in (("v1.0.0", LOCK, VERSION_END), ("Preview", PREVIEW_START, PREVIEW_END)):
        for i in range(len(text)):
            m.tick(start + (end - start) * i / len(text), 0.34, pan=-0.2 + 0.4 * i / len(text))
    m.add(BRACKETS, m.glide(330, 660, 0.09, 5), 0.2, send=0.3)
    m.add(TITLE_SHRINK, m.sweep_noise(TITLE_SMALL - TITLE_SHRINK, 2600, 400), 0.32, send=0.25)

    # Words leaving.
    m.click(DROP_NAME, 0.95, -0.2)
    m.click(DROP_VERSION, 0.95, 0.1)
    m.add(CLOSE, m.glide(300, 900, DOT - CLOSE, 1.4), 0.16, send=0.3)
    m.add(DOT, m.glide(980, 349, 0.07, 4), 0.2, send=0.3)

    # The dot, which is becoming the character again.
    for (t, _), f in zip(DOT_BEEPS, (349.23, 440.0, 523.25)):
        m.add(t, m.glide(f, f, 0.2, 8, (1.0, 0.5, 0.1)), 0.34, send=0.45)

    # Back into the terminal.
    m.add(WAKE, m.glide(240, 780, 0.2, 2.2, (1.0, 0.2)), 0.34, send=0.35)
    m.add(WAKE + 0.06, m.sweep_noise(LAND - WAKE - 0.06, 900, 3800), 0.14, -0.3, send=0.2)
    m.add(LAND, m.glide(150, 72, 0.14, 8), 0.8, -0.3, send=0.15)
    m.add(LAND, m.noise(0.03, 900, 5000, 8), 0.4, -0.3, send=0.15)
    m.tick(BLINK_3, 0.2, -0.3)
    m.tick(BLINK_3 + 0.12, 0.13, -0.3)


def finish(m):
    # A short room, different in each ear.
    n = int(0.9 * SR)
    decay = np.exp(-np.linspace(0, 7, n))
    for channel in (0, 1):
        room = m.rng.standard_normal(n) * decay
        b, a = butter(1, 5000 / (SR / 2))
        room = lfilter(b, a, room)
        wet = fftconvolve(m.wet[:, channel], room)[: len(m.dry)]
        m.dry[:, channel] += wet * 0.035
    return m.dry / np.abs(m.dry).max() * 10 ** (-3 / 20)


def synthesise():
    m = Mix(DURATION + 0.4)
    opening(m)
    return finish(m)


def write_audio(path, data=None):
    data = synthesise() if data is None else data
    pcm = (np.clip(data, -1, 1) * 32767).astype("<i2").tobytes()
    encoder = subprocess.Popen(
        ["ffmpeg", "-v", "error", "-y", "-f", "s16le", "-ar", str(SR), "-ac", "2", "-i", "-", path], stdin=subprocess.PIPE
    )
    encoder.communicate(pcm)


def main():
    kind = sys.argv[1]
    if kind == "video":
        write_video(sys.argv[2], "--draft" in sys.argv)
    elif kind == "audio":
        write_audio(sys.argv[2])
    elif kind == "frame":
        render(float(sys.argv[2])).save(sys.argv[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
