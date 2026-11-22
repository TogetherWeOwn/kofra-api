//! Passkeys: the WebAuthn checks against a software authenticator, and the
//! flows through the handler.

use kofra_account::memory::MemoryPorts as TestPorts;

include!("suites/passkeys.rs");
