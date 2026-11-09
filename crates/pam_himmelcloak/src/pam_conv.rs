/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Calls the login program's Linux-PAM conversation function.
//!
//! The planned messages from [`crate::conversation`] are sent through the
//! application's `pam_conv` callback. Answers are copied into zeroizing buffers,
//! and every response string the application allocated is wiped and freed.
//! Any unexpected reply from the application fails with `PAM_CONV_ERR`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use zeroize::{Zeroize, Zeroizing};

use crate::conversation::Message;

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_CONV_ERR: c_int = 19;
/// Linux-PAM item type that holds the application's `struct pam_conv`.
#[cfg_attr(test, allow(dead_code))]
const PAM_CONV_ITEM: c_int = 5;
/// Linux-PAM's limit on messages in one conversation call (`PAM_MAX_NUM_MSG`).
pub const MAX_MESSAGES: usize = 32;
/// Linux-PAM's limit on a single response (`PAM_MAX_RESP_SIZE`).
pub const MAX_RESPONSE_BYTES: usize = 512;

/// `struct pam_message`: style at offset 0, message pointer at offset 8 on 64-bit Linux.
#[repr(C)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// `struct pam_response`: the application allocates `resp` with malloc.
#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

pub type ConvCallback = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

/// `struct pam_conv`, supplied by the login program.
///
/// The fields are private, so safe code cannot build one: a `PamConv` comes
/// either from libpam through [`conversation_from_handle`] or from the unsafe
/// [`PamConv::from_raw`]. Both require the callback to follow the Linux-PAM
/// conversation contract, which is what lets [`converse`] be a safe function.
#[repr(C)]
pub struct PamConv {
    conv: Option<ConvCallback>,
    appdata_ptr: *mut c_void,
}

impl PamConv {
    /// Wrap a conversation callback and its application data.
    ///
    /// # Safety
    ///
    /// `conv` must follow the [pam_conv(3)] contract for the lifetime of the
    /// value: it may be called with `appdata_ptr`, it reads only the messages it
    /// is given, and when it returns `PAM_SUCCESS` it stores a malloc'd array of
    /// exactly `num_msg` responses whose non-null `resp` strings are malloc'd,
    /// NUL-terminated, writable, and owned by the caller afterwards.
    ///
    /// [pam_conv(3)]: https://man7.org/linux/man-pages/man3/pam_conv.3.html
    pub unsafe fn from_raw(conv: Option<ConvCallback>, appdata_ptr: *mut c_void) -> Self {
        Self { conv, appdata_ptr }
    }
}

/// One entry per message: input prompts return text, display-only messages return `None`.
pub type Answer = Option<Zeroizing<String>>;

#[cfg(not(test))]
extern "C" {
    fn pam_get_item(pamh: *const c_void, item_type: c_int, item: *mut *const c_void) -> c_int;
}

/// Look up the application's conversation structure.
///
/// The symbol is resolved from the libpam that loaded this module, so the
/// crate needs no libpam development files to build. Unit tests construct a
/// [`PamConv`] directly instead.
///
/// # Safety
///
/// `pamh` must be the live handle passed to one of this module's `pam_sm_*`
/// entry points, and the returned reference must not outlive that call.
#[cfg(not(test))]
pub unsafe fn conversation_from_handle<'a>(pamh: *mut c_void) -> Result<&'a PamConv, c_int> {
    if pamh.is_null() {
        return Err(PAM_CONV_ERR);
    }
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: the caller guarantees a live PAM handle; item is a valid out-pointer.
    let status = unsafe { pam_get_item(pamh, PAM_CONV_ITEM, &mut item) };
    if status != PAM_SUCCESS || item.is_null() {
        return Err(PAM_CONV_ERR);
    }
    // SAFETY: Linux-PAM stores the application's struct pam_conv for PAM_CONV and
    // keeps it alive for the handle's lifetime. Applications that load PAM modules
    // supply a callback meeting the contract documented on PamConv::from_raw.
    Ok(unsafe { &*item.cast::<PamConv>() })
}

/// Send `messages` in one conversation call and collect the answers.
pub fn converse(conv: &PamConv, messages: &[Message]) -> Result<Vec<Answer>, c_int> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }
    if messages.len() > MAX_MESSAGES {
        return Err(PAM_CONV_ERR);
    }
    let callback = conv.conv.ok_or(PAM_CONV_ERR)?;
    let texts = messages
        .iter()
        .map(|message| CString::new(message.text.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PAM_CONV_ERR)?;
    let structs: Vec<PamMessage> = messages
        .iter()
        .zip(&texts)
        .map(|(message, text)| PamMessage {
            msg_style: message.style.as_raw(),
            msg: text.as_ptr(),
        })
        .collect();
    // Linux-PAM passes an array of pointers to messages.
    let mut pointers: Vec<*const PamMessage> = structs.iter().map(std::ptr::from_ref).collect();
    let mut responses: *mut PamResponse = std::ptr::null_mut();

    // SAFETY: every pointer refers to a live CString or PamMessage owned above,
    // and the count matches the array length (at most MAX_MESSAGES).
    let status = unsafe {
        callback(
            messages.len() as c_int,
            pointers.as_mut_ptr(),
            &mut responses,
            conv.appdata_ptr,
        )
    };
    // On failure the application keeps ownership of anything it allocated;
    // freeing it here could double free, so it is left alone.
    if status != PAM_SUCCESS || responses.is_null() {
        return Err(PAM_CONV_ERR);
    }
    // SAFETY: a PamConv can only be created under the pam_conv contract (see
    // PamConv::from_raw), so on success this is a malloc'd array with one
    // response per message, and ownership has passed to the module.
    let responses = unsafe { Responses::take(responses, messages.len()) };
    responses.answers(messages)
}

/// Owns the application's response array and wipes and frees it on drop.
struct Responses {
    array: *mut PamResponse,
    len: usize,
}

impl Responses {
    /// # Safety
    ///
    /// `array` must be a malloc'd array of `len` responses owned by the caller.
    unsafe fn take(array: *mut PamResponse, len: usize) -> Self {
        Self { array, len }
    }

    fn entry(&self, index: usize) -> &PamResponse {
        debug_assert!(index < self.len);
        // SAFETY: index is below len, and the array is live while self exists.
        unsafe { &*self.array.add(index) }
    }

    fn answers(&self, messages: &[Message]) -> Result<Vec<Answer>, c_int> {
        let mut answers = Vec::with_capacity(messages.len());
        for (index, message) in messages.iter().enumerate() {
            if !message.style.expects_input() {
                answers.push(None);
                continue;
            }
            let reply = self.entry(index).resp;
            if reply.is_null() {
                return Err(PAM_CONV_ERR);
            }
            // SAFETY: a non-null response is a NUL-terminated string from the application.
            let bytes = unsafe { CStr::from_ptr(reply) }.to_bytes();
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(PAM_CONV_ERR);
            }
            let text = std::str::from_utf8(bytes).map_err(|_| PAM_CONV_ERR)?;
            answers.push(Some(Zeroizing::new(text.to_owned())));
        }
        Ok(answers)
    }
}

impl Drop for Responses {
    fn drop(&mut self) {
        for index in 0..self.len {
            let reply = self.entry(index).resp;
            if !reply.is_null() {
                // SAFETY: the application allocated each response with malloc and
                // passed ownership to the module; it is wiped before it is freed.
                unsafe {
                    wipe_c_string(reply);
                    libc::free(reply.cast());
                }
            }
        }
        // SAFETY: the array itself was malloc'd by the application.
        unsafe { libc::free(self.array.cast()) };
    }
}

/// Overwrite a NUL-terminated string's bytes with zeros.
///
/// # Safety
///
/// `text` must point to a writable, NUL-terminated string.
unsafe fn wipe_c_string(text: *mut c_char) {
    // SAFETY: guaranteed by the caller.
    let len = unsafe { libc::strlen(text) };
    // SAFETY: the len bytes before the terminator are writable.
    unsafe { std::slice::from_raw_parts_mut(text.cast::<u8>(), len) }.zeroize();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::conversation::MessageStyle;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    type Replies = Vec<Option<Vec<u8>>>;

    fn replies(answers: &[Option<&str>]) -> Replies {
        answers
            .iter()
            .map(|a| a.map(|s| s.as_bytes().to_vec()))
            .collect()
    }

    /// Scripted login program: records each prompt and returns preset answers.
    /// Queued answer lists are used one per call, then `answers` for any later call.
    pub(crate) struct Script {
        pub status: c_int,
        pub null_array: bool,
        pub answers: Replies,
        pub queue: RefCell<VecDeque<Replies>>,
        pub seen: RefCell<Vec<(c_int, String)>>,
        pub calls: RefCell<usize>,
    }

    impl Script {
        pub fn answering(answers: &[Option<&str>]) -> Self {
            Self {
                status: PAM_SUCCESS,
                null_array: false,
                answers: replies(answers),
                queue: RefCell::new(VecDeque::new()),
                seen: RefCell::new(Vec::new()),
                calls: RefCell::new(0),
            }
        }

        pub fn then(self, answers: &[Option<&str>]) -> Self {
            self.queue.borrow_mut().push_back(replies(answers));
            self
        }

        pub fn conv(&self) -> PamConv {
            // SAFETY: `scripted` follows the pam_conv contract (calloc'd array and
            // strings), and the script outlives every PamConv a test builds from it.
            unsafe { PamConv::from_raw(Some(scripted), std::ptr::from_ref(self).cast_mut().cast()) }
        }
    }

    unsafe extern "C" fn scripted(
        num_msg: c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int {
        let script = unsafe { &*appdata_ptr.cast::<Script>() };
        *script.calls.borrow_mut() += 1;
        let count = num_msg as usize;
        for index in 0..count {
            let message = unsafe { &**msg.add(index) };
            let text = unsafe { CStr::from_ptr(message.msg) }
                .to_string_lossy()
                .into_owned();
            script.seen.borrow_mut().push((message.msg_style, text));
        }
        if script.status != PAM_SUCCESS {
            return script.status;
        }
        if script.null_array {
            unsafe { *resp = std::ptr::null_mut() };
            return PAM_SUCCESS;
        }
        let array = unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) }
            .cast::<PamResponse>();
        let answers = script
            .queue
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| script.answers.clone());
        for (index, answer) in answers.iter().take(count).enumerate() {
            if let Some(bytes) = answer {
                let copy = unsafe { libc::calloc(bytes.len() + 1, 1) }.cast::<u8>();
                unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len()) };
                unsafe { (*array.add(index)).resp = copy.cast() };
            }
        }
        unsafe { *resp = array };
        PAM_SUCCESS
    }

    fn message(style: MessageStyle, text: &str) -> Message {
        Message {
            style,
            text: text.into(),
        }
    }

    fn texts(answers: Vec<Answer>) -> Vec<Option<String>> {
        answers
            .into_iter()
            .map(|a| a.map(|s| s.as_str().to_owned()))
            .collect()
    }

    #[test]
    fn hidden_and_visible_prompts_complete_a_round_trip() {
        let script = Script::answering(&[Some("alice"), Some("correct horse")]);
        let answers = converse(
            &script.conv(),
            &[
                message(MessageStyle::VisibleInput, "Username: "),
                message(MessageStyle::HiddenInput, "Password: "),
            ],
        )
        .unwrap();
        assert_eq!(
            texts(answers),
            [Some("alice".to_owned()), Some("correct horse".to_owned())]
        );
        assert_eq!(
            *script.seen.borrow(),
            [(2, "Username: ".to_owned()), (1, "Password: ".to_owned())]
        );
        assert_eq!(*script.calls.borrow(), 1);
    }

    #[test]
    fn display_messages_return_no_answer_even_if_the_application_replies() {
        let script = Script::answering(&[Some("ignored"), None, Some("bob")]);
        let answers = converse(
            &script.conv(),
            &[
                message(MessageStyle::Information, "Check your phone"),
                message(MessageStyle::Error, "Code expired"),
                message(MessageStyle::VisibleInput, "Username: "),
            ],
        )
        .unwrap();
        assert_eq!(texts(answers), [None, None, Some("bob".to_owned())]);
        assert_eq!(script.seen.borrow()[0].0, 4);
        assert_eq!(script.seen.borrow()[1].0, 3);
    }

    #[test]
    fn an_empty_answer_is_kept_as_an_empty_string() {
        let script = Script::answering(&[Some("")]);
        let answers = converse(
            &script.conv(),
            &[message(MessageStyle::HiddenInput, "Password: ")],
        )
        .unwrap();
        assert_eq!(texts(answers), [Some(String::new())]);
    }

    #[test]
    fn application_failure_is_reported_as_a_conversation_error() {
        for status in [PAM_CONV_ERR, 7, 5] {
            let mut script = Script::answering(&[Some("alice")]);
            script.status = status;
            assert_eq!(
                converse(
                    &script.conv(),
                    &[message(MessageStyle::VisibleInput, "Username: ")]
                )
                .unwrap_err(),
                PAM_CONV_ERR
            );
        }
    }

    #[test]
    fn missing_callback_or_response_array_fails() {
        // SAFETY: a missing callback is never called.
        let conv = unsafe { PamConv::from_raw(None, std::ptr::null_mut()) };
        let prompt = [message(MessageStyle::HiddenInput, "Password: ")];
        assert_eq!(converse(&conv, &prompt).unwrap_err(), PAM_CONV_ERR);

        let mut script = Script::answering(&[Some("secret")]);
        script.null_array = true;
        assert_eq!(converse(&script.conv(), &prompt).unwrap_err(), PAM_CONV_ERR);
    }

    #[test]
    fn missing_invalid_or_oversized_answers_fail() {
        let prompt = [message(MessageStyle::HiddenInput, "Password: ")];
        let missing = Script::answering(&[None]);
        assert_eq!(
            converse(&missing.conv(), &prompt).unwrap_err(),
            PAM_CONV_ERR
        );

        let mut invalid = Script::answering(&[]);
        invalid.answers = vec![Some(vec![0xff, 0xfe])];
        assert_eq!(
            converse(&invalid.conv(), &prompt).unwrap_err(),
            PAM_CONV_ERR
        );

        let at_limit = "x".repeat(MAX_RESPONSE_BYTES);
        let script = Script::answering(&[Some(&at_limit)]);
        assert!(converse(&script.conv(), &prompt).is_ok());
        let over_limit = "x".repeat(MAX_RESPONSE_BYTES + 1);
        let script = Script::answering(&[Some(&over_limit)]);
        assert_eq!(converse(&script.conv(), &prompt).unwrap_err(), PAM_CONV_ERR);
    }

    #[test]
    fn bad_message_lists_never_reach_the_application() {
        let script = Script::answering(&[]);
        assert!(converse(&script.conv(), &[]).unwrap().is_empty());

        let too_many: Vec<_> = (0..=MAX_MESSAGES)
            .map(|_| message(MessageStyle::Information, "x"))
            .collect();
        assert_eq!(
            converse(&script.conv(), &too_many).unwrap_err(),
            PAM_CONV_ERR
        );

        let nul = [message(MessageStyle::Information, "bad\0text")];
        assert_eq!(converse(&script.conv(), &nul).unwrap_err(), PAM_CONV_ERR);
        assert_eq!(*script.calls.borrow(), 0);
    }

    #[test]
    fn the_maximum_message_count_is_accepted() {
        let answers: Vec<Option<&str>> = vec![None; MAX_MESSAGES];
        let script = Script::answering(&answers);
        let messages: Vec<_> = (0..MAX_MESSAGES)
            .map(|_| message(MessageStyle::Information, "x"))
            .collect();
        assert_eq!(
            converse(&script.conv(), &messages).unwrap().len(),
            MAX_MESSAGES
        );
    }

    #[test]
    fn response_strings_are_wiped_before_they_are_freed() {
        let text = CString::new("secret").unwrap();
        // SAFETY: strdup returns a writable malloc'd copy, freed below.
        let copy = unsafe { libc::strdup(text.as_ptr()) };
        unsafe { wipe_c_string(copy) };
        let bytes = unsafe { std::slice::from_raw_parts(copy.cast::<u8>(), 6) };
        assert!(bytes.iter().all(|&b| b == 0));
        unsafe { libc::free(copy.cast()) };
    }
}
