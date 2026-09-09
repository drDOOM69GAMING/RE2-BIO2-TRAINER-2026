use crate::process::ProcessHandle;

#[derive(Clone, Copy, PartialEq)]
pub enum CheatValue {
    Float(f32),
}

pub struct Cheat {
    pub label: String,
    pub offsets: Vec<isize>,
    pub absolute: bool,
    pub target: CheatValue,
    pub enabled: bool,
}

impl Cheat {
    pub fn apply(&self, h: ProcessHandle, module_base: usize, tick_addr: &mut usize) -> bool {
        let addr = if *tick_addr != 0 {
            *tick_addr
        } else if self.absolute {
            self.offsets[0] as usize
        } else {
            match unsafe { super::process::resolve_chain(h, module_base, &self.offsets) } {
                Some(a) => a,
                None => return false,
            }
        };
        *tick_addr = addr;
        match self.target {
            CheatValue::Float(t) => {
                match unsafe { super::process::read_memory::<f32>(h, addr) } {
                    Some(v) if v != t => unsafe { super::process::write_memory(h, addr, &t) },
                    Some(_) => true,
                    None => false,
                }
            }
        }
    }

    pub fn resolve_here(&self, h: ProcessHandle, module_base: usize) -> Option<usize> {
        if self.absolute {
            Some(self.offsets[0] as usize)
        } else {
            unsafe { super::process::resolve_chain(h, module_base, &self.offsets) }
        }
    }
}