//! The account service's `flows` suite (`kofra-account/tests/suites/flows.rs`)
//! on the SQL store over SQLite: every statement the D1 adapter runs.

mod common;

use common::ports::TestPorts;

include!("../../kofra-account/tests/suites/flows.rs");
