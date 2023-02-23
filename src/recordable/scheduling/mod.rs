use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum SchedulerEvent {
    Start { pc: u64 },
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Scheduling {
    pub tid: u32, // TODO: proper type
    pub event: SchedulerEvent,
}
