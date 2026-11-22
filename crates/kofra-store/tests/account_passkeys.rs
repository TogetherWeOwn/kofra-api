//! The account service's `passkeys` suite
//! (`kofra-account/tests/suites/passkeys.rs`) on the SQL store over SQLite.

mod common;

use common::ports::TestPorts;

include!("../../kofra-account/tests/suites/passkeys.rs");
