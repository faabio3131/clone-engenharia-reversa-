import { describe, expect, it } from "vitest";
import { hardwareInstructionChannelsResultSchema } from "./hardwareInstructionChannels.js";
import { analyzeProcedureHardwareInstructions } from "./hardwareInstructionClassifiers.js";

const procId = (name: string, address: string) => ({
  name,
  address,
  classification: null,
  body: { available: false as const, reason: "fixture" },
});

describe("analyzeProcedureHardwareInstructions ARM, AArch64, and RISC-V", () => {
  it("classifies ARM Cortex-M and CP15 system registers, interrupt masks, barriers, and sleep instructions", () => {
    const res = analyzeProcedureHardwareInstructions({
      procedure: procId("Reset_Handler", "0x08000100"),
      architecture: "arm",
      instructions: [
        "0x08000100: cpsid i",
        "0x08000102: mrs r0, primask",
        "0x08000106: msr msp_ns, r1",
        "0x0800010a: mcr p15, #0, r0, c12, c0, #0",
        "0x0800010e: dsb.w sy",
        "0x08000112: isb",
        "0x08000116: wfi",
        "0x08000118: bx lr",
      ],
    });
    expect(hardwareInstructionChannelsResultSchema.safeParse(res).success).toBe(
      true,
    );
    expect(res.matched_instruction_count).toBe(7);
    expect(res.channels[0]).toMatchObject({
      instruction_address: "0x08000100",
      mnemonic: "cpsid",
      category: "interrupt_mask",
      direction: "write",
      target: "CPS:I",
    });
    expect(res.channels[1]).toMatchObject({
      mnemonic: "mrs",
      category: "system_register",
      direction: "read",
      target: "PRIMASK",
    });
    expect(res.channels[2]).toMatchObject({
      mnemonic: "msr",
      direction: "write",
      target: "MSP_NS",
      target_description: "Main Stack Pointer (Non-secure)",
    });
    expect(res.channels[3]).toMatchObject({
      mnemonic: "mcr",
      category: "coprocessor",
      direction: "write",
      target: "P15:0,c12,c0,0",
      target_description: "Vector Base Address Register (VBAR)",
    });
  });

  it("classifies AArch64 EL system registers and RISC-V CSR pseudo and explicit operations", () => {
    const arm64 = analyzeProcedureHardwareInstructions({
      procedure: procId("el3_init", "0x4000"),
      architecture: "arm64",
      instructions: [
        "0x4000 mrs x0, CurrentEL",
        "0x4004 msr vbar_el1, x1",
        "0x4008 msr s3_0_c15_c2_0, x2",
        "0x400c tlbi vmalle1",
        "0x4010 eret",
      ],
    });
    expect(arm64.matched_instruction_count).toBe(5);
    expect(arm64.channels[1]).toMatchObject({
      target: "VBAR_EL1",
      direction: "write",
      target_basis: "architecture_manual",
    });
    expect(arm64.channels[2]).toMatchObject({
      target: "S3_0_C15_C2_0",
      target_basis: "numeric_encoding",
    });

    const rv = analyzeProcedureHardwareInstructions({
      procedure: procId("trap_init", "0x80000000"),
      architecture: "riscv",
      instructions: [
        "0x80000000: csrrw x0, mtvec, a0",
        "0x80000004: csrrs a1, mcause, x0",
        "0x80000008: csrsi mstatus, 8",
        "0x8000000c: csrw pmpcfg0, a2",
        "0x80000010: sfence.vma",
        "0x80000014: mret",
      ],
    });
    expect(rv.matched_instruction_count).toBe(6);
    expect(rv.channels[0]).toMatchObject({
      category: "csr",
      direction: "write",
      target: "mtvec",
    });
    expect(rv.channels[1]).toMatchObject({
      category: "csr",
      direction: "read",
      target: "mcause",
    });
    expect(rv.channels[2]).toMatchObject({
      direction: "read_modify_write",
      target: "mstatus",
    });
    expect(rv.channels[3]).toMatchObject({
      direction: "write",
      target: "pmpcfg0",
    });
  });
});

describe("analyzeProcedureHardwareInstructions Xtensa, MIPS, x86, and controls", () => {
  it("classifies Xtensa special registers, MIPS CP0, and x86 Intel/AT&T port I/O, MSR, and CR moves", () => {
    const xtensa = analyzeProcedureHardwareInstructions({
      procedure: procId("xt_ints_off", "0x40080100"),
      architecture: "xtensa",
      instructions: ["rsil a2, 3", "rsr.ccount a3", "wsr a4, vecbase", "memw"],
    });
    expect(xtensa.matched_instruction_count).toBe(4);
    expect(xtensa.channels[1]).toMatchObject({
      category: "special_register",
      direction: "read",
      target: "CCOUNT",
    });
    expect(xtensa.channels[2]).toMatchObject({
      direction: "write",
      target: "VECBASE",
    });

    const mips = analyzeProcedureHardwareInstructions({
      procedure: procId("mips_exc", "0xbfc00380"),
      architecture: "mips",
      instructions: ["di", "mfc0 $k0, $13", "mtc0 $k0, $12, 0", "eret"],
    });
    expect(mips.matched_instruction_count).toBe(4);
    expect(mips.channels[1]).toMatchObject({
      category: "coprocessor",
      direction: "read",
      target: "CP0:$13",
    });

    const x86 = analyzeProcedureHardwareInstructions({
      procedure: procId("pci_read_cfg", "0xfff00100"),
      architecture: "x86_64",
      instructions: [
        "0xfff00100: cli",
        "0xfff00101: out 0xcf8, eax",
        "0xfff00103: in eax, dx",
        "0xfff00104: outb %al, $0x80",
        "0xfff00106: rdmsr",
        "0xfff00108: mov cr3, rax",
        "0xfff0010b: movq %cr0, %rbx",
      ],
    });
    expect(x86.matched_instruction_count).toBe(7);
    expect(x86.channels[1]).toMatchObject({
      category: "port_io",
      direction: "write",
      target: "0xcf8",
      target_basis: "architecture_manual",
    });
    expect(x86.channels[2]).toMatchObject({
      category: "port_io",
      direction: "read",
      target: null,
      target_basis: "unresolved_register",
    });
    expect(x86.channels[3]).toMatchObject({
      category: "port_io",
      direction: "write",
      target: "0x80",
    });
    expect(x86.channels[5]).toMatchObject({
      category: "system_register",
      direction: "write",
      target: "CR3",
    });
    expect(x86.channels[6]).toMatchObject({
      category: "system_register",
      direction: "read",
      target: "CR0",
    });
    expect(x86.summary.unresolved_dynamic_count).toBe(2);
    expect(
      x86.limitations.some((l) => l.includes("general-purpose register")),
    ).toBe(true);
  });

  it("returns zero channels for pure ALU and memory load/store instructions", () => {
    const pureAlu = analyzeProcedureHardwareInstructions({
      procedure: procId("memcpy_words", "0x1000"),
      architecture: "arm",
      instructions: [
        "0x1000: push {r4, lr}",
        "0x1002: ldr r3, [r1], #4",
        "0x1006: str r3, [r0], #4",
        "0x100a: subs r2, r2, #1",
        "0x100c: bne 0x1002",
        "0x100e: pop {r4, pc}",
      ],
    });
    expect(pureAlu.matched_instruction_count).toBe(0);
    expect(pureAlu.channels).toEqual([]);
  });
});
