#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NewClone {
    pub parent_pid: i32,
    pub child_pid: i32,
}
