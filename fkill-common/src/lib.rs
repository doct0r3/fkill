#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NewClone {
    pub parent_pid: i32,
    pub child_pid: i32,
}


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PidBuf {
    pub pids: [i32; 10],
}