use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
enum SchedulerData {
    Start { time_delta: u64 },
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Scheduling {
    pub tid: u32, // TODO: proper type
    pub pc: u64,
    data: SchedulerData,
}
