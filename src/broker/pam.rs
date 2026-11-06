//! Approval through Linux-PAM, using the same passwords and account rules as
//! the rest of the system. Prompts go only to the controlling terminal, so a
//! caller's stdin or stdout redirection cannot supply or capture a password.

use crate::request::escape_display;
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_void};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_TTY: c_int = 3;
const PAM_RUSER: c_int = 8;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;
const MAX_INPUT: usize = 1024;

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
    fn pam_authenticate(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_set_item(handle: *mut PamHandle, item: c_int, value: *const c_void) -> c_int;
    fn pam_strerror(handle: *mut PamHandle, code: c_int) -> *const c_char;
}

pub struct Tty {
    file: File,
    cancelled: Cell<bool>,
}

impl Tty {
    pub fn open() -> io::Result<Tty> {
        Ok(Tty {
            file: OpenOptions::new().read(true).write(true).open("/dev/tty")?,
            cancelled: Cell::new(false),
        })
    }

    pub fn say(&self, text: &str) {
        let _ = (&self.file).write_all(text.as_bytes());
    }

    /// True once a prompt has ended in EOF, so PAM's failure is not a wrong password.
    pub fn cancelled(&self) -> bool {
        self.cancelled.get()
    }

    /// Reads one line. Returns None on EOF, which is how the user cancels.
    /// The returned buffer may hold a password, so callers wipe it.
    pub fn prompt(&self, text: &str, echo: bool) -> Option<Vec<u8>> {
        self.say(text);
        let fd = self.file.as_raw_fd();

        // Ctrl-C must not kill us while echo is off, which would leave the
        // user's terminal without echo.
        let saved_signals: Vec<_> = [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP]
            .iter()
            .map(|s| (*s, unsafe { libc::signal(*s, libc::SIG_IGN) }))
            .collect();

        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        let have_termios = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
        if have_termios && !echo {
            let mut quiet = saved;
            quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) };
        }

        // Sized up front: growing would leave password fragments in freed memory.
        let mut line = Vec::with_capacity(MAX_INPUT);
        let mut byte = [0u8; 1];
        let mut got_line = false;
        loop {
            match (&self.file).read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => {
                    got_line = true;
                    break;
                }
                Ok(1) if line.len() < MAX_INPUT => line.push(byte[0]),
                Ok(1) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }

        if have_termios && !echo {
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };
            self.say("\n");
        }
        for (sig, previous) in saved_signals {
            unsafe { libc::signal(sig, previous) };
        }
        wipe(&mut byte);

        if got_line {
            Some(line)
        } else {
            wipe(&mut line);
            self.cancelled.set(true);
            None
        }
    }
}

fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Copies into memory PAM will own and free.
fn pam_string(bytes: &[u8]) -> *mut c_char {
    unsafe {
        let p = libc::malloc(bytes.len() + 1) as *mut u8;
        if !p.is_null() {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
            *p.add(bytes.len()) = 0;
        }
        p as *mut c_char
    }
}

extern "C" fn conversation(
    count: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if count <= 0 || messages.is_null() || responses.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    let tty = unsafe { &*(appdata as *const Tty) };
    let replies =
        unsafe { libc::calloc(count as usize, std::mem::size_of::<PamResponse>()) } as *mut PamResponse;
    if replies.is_null() {
        return PAM_BUF_ERR;
    }

    let free_all = |filled: usize| unsafe {
        for i in 0..filled {
            let resp = (*replies.add(i)).resp;
            if !resp.is_null() {
                wipe(std::slice::from_raw_parts_mut(
                    resp as *mut u8,
                    libc::strlen(resp),
                ));
                libc::free(resp as *mut c_void);
            }
        }
        libc::free(replies as *mut c_void);
    };

    for i in 0..count as usize {
        let msg = unsafe { &**messages.add(i) };
        let text = if msg.msg.is_null() {
            String::new()
        } else {
            let raw = unsafe { CStr::from_ptr(msg.msg) };
            escape_display(&raw.to_string_lossy())
        };
        match msg.msg_style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                let echo = msg.msg_style == PAM_PROMPT_ECHO_ON;
                let Some(mut input) = tty.prompt(&text, echo) else {
                    free_all(i);
                    return PAM_CONV_ERR;
                };
                // Input with NUL would be cut short by C string handling.
                let usable = !input.contains(&0);
                let copy = if usable {
                    pam_string(&input)
                } else {
                    std::ptr::null_mut()
                };
                wipe(&mut input);
                if copy.is_null() {
                    free_all(i);
                    return PAM_CONV_ERR;
                }
                unsafe { (*replies.add(i)).resp = copy };
            }
            PAM_ERROR_MSG | PAM_TEXT_INFO => tty.say(&format!("{text}\n")),
            _ => {
                free_all(i);
                return PAM_CONV_ERR;
            }
        }
    }
    unsafe { *responses = replies };
    PAM_SUCCESS
}

/// Checks the approver's credentials and that their account is usable.
/// Accounts with an empty password cannot approve.
pub fn authenticate(
    service: &str,
    approver: &str,
    requester: &str,
    tty_name: &str,
    tty: &Tty,
) -> Result<(), String> {
    let cstr = |s: &str| CString::new(s).map_err(|_| "name contains NUL".to_string());
    let service = cstr(service)?;
    let user = cstr(approver)?;
    let ruser = cstr(requester)?;
    let tty_item = cstr(tty_name)?;

    let conv = PamConv {
        conv: conversation,
        appdata_ptr: tty as *const Tty as *mut c_void,
    };
    let mut handle: *mut PamHandle = std::ptr::null_mut();
    let mut status = unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    if status != PAM_SUCCESS {
        return Err("cannot start PAM".to_string());
    }
    unsafe {
        pam_set_item(handle, PAM_RUSER, ruser.as_ptr() as *const c_void);
        pam_set_item(handle, PAM_TTY, tty_item.as_ptr() as *const c_void);
        status = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK);
        if status == PAM_SUCCESS {
            status = pam_acct_mgmt(handle, PAM_DISALLOW_NULL_AUTHTOK);
        }
    }
    let result = if status == PAM_SUCCESS {
        Ok(())
    } else {
        let message = unsafe { pam_strerror(handle, status) };
        Err(if message.is_null() {
            format!("PAM error {status}")
        } else {
            unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned()
        })
    };
    unsafe { pam_end(handle, status) };
    result
}
