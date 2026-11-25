import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import type {
  HardwareChannelCategory,
  HardwareInstructionArchitecture,
  HardwareInstructionChannel,
  HardwareInstructionChannelsResult,
} from "./hardwareInstructionChannels.js";
import {
  classifyRiscvInstruction,
  type ClassifiedInstruction,
} from "./hardwareInstructionRiscv.js";
import { classifyX86Instruction } from "./hardwareInstructionX86.js";

const ARM_SYSREG_DESCRIPTIONS: Readonly<Record<string, string>> = {
  MSP: "Main Stack Pointer",
  PSP: "Process Stack Pointer",
  MSPLIM: "Main Stack Pointer Limit Register",
  PSPLIM: "Process Stack Pointer Limit Register",
  PRIMASK: "Exception Priority Mask Register",
  BASEPRI: "Base Priority Mask Register",
  BASEPRI_MAX: "Base Priority Mask Conditional Write",
  FAULTMASK: "Fault Mask Register",
  CONTROL: "Special-Purpose Control Register",
  IPSR: "Interrupt Program Status Register",
  EPSR: "Execution Program Status Register",
  APSR: "Application Program Status Register",
  XPSR: "Combined Program Status Register",
  CPSR: "Current Program Status Register",
  SPSR: "Saved Program Status Register",
  CURRENTEL: "Current Exception Level",
  DAIF: "Interrupt Mask Bits (Debug, SError, IRQ, FIQ)",
  DAIFSET: "Set DAIF Interrupt Mask Bits",
  DAIFCLR: "Clear DAIF Interrupt Mask Bits",
  NZCV: "Condition Flags",
};

const describeArmSystemReg = (
  raw: string,
): {
  readonly target: string;
  readonly description: string | null;
  readonly basis: ClassifiedInstruction["target_basis"];
} => {
  const upper = raw.toUpperCase().replace(/_NS$/u, "");
  const fullUpper = raw.toUpperCase();
  const exact = ARM_SYSREG_DESCRIPTIONS[upper];
  if (exact !== undefined) {
    return {
      target: fullUpper,
      description: fullUpper.endsWith("_NS") ? `${exact} (Non-secure)` : exact,
      basis: "architecture_manual",
    };
  }
  if (
    /^(?:SCTLR|VBAR|TTBR0|TTBR1|TCR|MAIR|ESR|FAR|ELR|SPSR|SCR|HCR|CPACR|SP|TPIDR)_EL[0-3]$/u.test(
      fullUpper,
    )
  ) {
    return {
      target: fullUpper,
      description: `AArch64 System Register ${fullUpper}`,
      basis: "architecture_manual",
    };
  }
  if (/^S[0-3]_[0-7]_C[0-9]+_C[0-9]+_[0-7]$/u.test(fullUpper)) {
    return { target: fullUpper, description: null, basis: "numeric_encoding" };
  }
  return { target: fullUpper, description: null, basis: "architecture_manual" };
};

const ARM_BARRIER_AND_WAIT: Readonly<
  Record<
    string,
    { readonly category: HardwareChannelCategory; readonly description: string }
  >
> = {
  dsb: {
    category: "memory_barrier",
    description: "Data Synchronization Barrier",
  },
  dmb: { category: "memory_barrier", description: "Data Memory Barrier" },
  isb: {
    category: "memory_barrier",
    description: "Instruction Synchronization Barrier",
  },
  wfi: { category: "power_or_wait", description: "Wait For Interrupt" },
  wfe: { category: "power_or_wait", description: "Wait For Event" },
  sev: { category: "power_or_wait", description: "Send Event" },
  sevl: { category: "power_or_wait", description: "Send Event Local" },
  svc: { category: "privilege_or_trap", description: "Supervisor Call" },
  hvc: { category: "privilege_or_trap", description: "Hypervisor Call" },
  smc: { category: "privilege_or_trap", description: "Secure Monitor Call" },
  eret: { category: "privilege_or_trap", description: "Exception Return" },
  bkpt: { category: "privilege_or_trap", description: "Software Breakpoint" },
  brk: { category: "privilege_or_trap", description: "AArch64 Breakpoint" },
};

const ARM_COPROC_MNEMONICS: ReadonlySet<string> = new Set([
  "mcr",
  "mcr2",
  "mrc",
  "mrc2",
]);

const ARM64_MAINT_MNEMONICS: ReadonlySet<string> = new Set([
  "tlbi",
  "ic",
  "dc",
]);

const classifyArmCoprocessor = (
  mnemonic: string,
  baseMnem: string,
  operands: readonly string[],
): ClassifiedInstruction | null => {
  if (!ARM_COPROC_MNEMONICS.has(baseMnem) || operands.length < 5) return null;
  const coproc = operands[0]!.toUpperCase();
  const opc1 = operands[1]!.replace(/^#/u, "");
  const crn = operands[3]!.toLowerCase();
  const crm = operands[4]!.toLowerCase();
  const opc2 = (operands[5] ?? "0").replace(/^#/u, "");
  const target = `${coproc}:${opc1},${crn},${crm},${opc2}`;
  const description =
    target === "P15:0,c1,c0,0"
      ? "System Control Register (SCTLR)"
      : target === "P15:0,c12,c0,0"
        ? "Vector Base Address Register (VBAR)"
        : `ARM Coprocessor ${target}`;
  return {
    mnemonic,
    category: "coprocessor",
    direction: baseMnem.startsWith("mrc") ? "read" : "write",
    target,
    target_description: description,
    target_basis: "architecture_manual",
  };
};

const classifyArmOrArm64 = (
  mnemonic: string,
  operands: readonly string[],
  isArm64: boolean,
): ClassifiedInstruction | null => {
  const baseMnem = mnemonic.replace(/\.(?:w|n)$/u, "");
  const fixed = ARM_BARRIER_AND_WAIT[baseMnem];
  if (fixed !== undefined) {
    return {
      mnemonic,
      category: fixed.category,
      direction: "control",
      target: null,
      target_description: fixed.description,
      target_basis: "not_applicable",
    };
  }

  if ((baseMnem === "mrs" || baseMnem === "msr") && operands.length >= 2) {
    const isRead = baseMnem === "mrs";
    const reg = describeArmSystemReg(isRead ? operands[1]! : operands[0]!);
    return {
      mnemonic,
      category: "system_register",
      direction: isRead ? "read" : "write",
      target: reg.target,
      target_description: reg.description,
      target_basis: reg.basis,
    };
  }

  if (!isArm64 && (baseMnem === "cpsid" || baseMnem === "cpsie")) {
    const flags = (operands[0] ?? "").toUpperCase() || "I";
    return {
      mnemonic,
      category: "interrupt_mask",
      direction: "write",
      target: `CPS:${flags}`,
      target_description:
        baseMnem === "cpsid"
          ? `Disable interrupt mask (${flags})`
          : `Enable interrupt mask (${flags})`,
      target_basis: "architecture_manual",
    };
  }

  if (!isArm64) return classifyArmCoprocessor(mnemonic, baseMnem, operands);

  if (ARM64_MAINT_MNEMONICS.has(baseMnem)) {
    const op0 = operands[0];
    return {
      mnemonic,
      category: "cache_or_tlb",
      direction: "control",
      target: op0 !== undefined ? op0.toUpperCase() : null,
      target_description: `AArch64 ${baseMnem.toUpperCase()} maintenance`,
      target_basis:
        op0 !== undefined ? "architecture_manual" : "not_applicable",
    };
  }

  return null;
};

const XTENSA_SR_BASES: Readonly<
  Record<string, ClassifiedInstruction["direction"]>
> = {
  rsr: "read",
  wsr: "write",
  xsr: "read_modify_write",
};

const XTENSA_BARRIERS: ReadonlySet<string> = new Set([
  "memw",
  "extw",
  "isync",
  "dsync",
  "esync",
  "rsync",
]);

const XTENSA_TRAPS: ReadonlySet<string> = new Set([
  "rfe",
  "rfi",
  "syscall",
  "break",
]);

const classifyXtensa = (
  mnemonic: string,
  operands: readonly string[],
): ClassifiedInstruction | null => {
  const dotParts = mnemonic.split(".");
  const srDir = XTENSA_SR_BASES[dotParts[0]!];
  if (srDir !== undefined) {
    const srRaw = dotParts[1] ?? operands[1] ?? operands[0];
    if (srRaw === undefined) return null;
    const sr = srRaw.toUpperCase();
    return {
      mnemonic,
      category: "special_register",
      direction: srDir,
      target: sr,
      target_description: `Xtensa Special Register ${sr}`,
      target_basis: /^[0-9]+$/u.test(sr)
        ? "numeric_encoding"
        : "architecture_manual",
    };
  }
  if (mnemonic === "rsil" || mnemonic === "waiti") {
    return {
      mnemonic,
      category: mnemonic === "rsil" ? "interrupt_mask" : "power_or_wait",
      direction: mnemonic === "rsil" ? "read_modify_write" : "control",
      target: "PS.INTLEVEL",
      target_description:
        mnemonic === "rsil"
          ? "Read and Set Xtensa Interrupt Level"
          : "Wait for Interrupt at specified level",
      target_basis: "architecture_manual",
    };
  }
  if (XTENSA_BARRIERS.has(mnemonic) || XTENSA_TRAPS.has(mnemonic)) {
    return {
      mnemonic,
      category: XTENSA_BARRIERS.has(mnemonic)
        ? "memory_barrier"
        : "privilege_or_trap",
      direction: "control",
      target: null,
      target_description: `Xtensa ${mnemonic.toUpperCase()}`,
      target_basis: "not_applicable",
    };
  }
  return null;
};

const MIPS_CP0_MOVES: ReadonlySet<string> = new Set([
  "mfc0",
  "dmfc0",
  "mtc0",
  "dmtc0",
]);

const MIPS_FIXED_OPS: Readonly<
  Record<
    string,
    { readonly category: HardwareChannelCategory; readonly description: string }
  >
> = {
  eret: { category: "privilege_or_trap", description: "MIPS ERET" },
  deret: { category: "privilege_or_trap", description: "MIPS DERET" },
  syscall: { category: "privilege_or_trap", description: "MIPS SYSCALL" },
  sync: { category: "memory_barrier", description: "MIPS SYNC barrier" },
  ehb: { category: "memory_barrier", description: "MIPS EHB barrier" },
  wait: { category: "power_or_wait", description: "MIPS Wait for Interrupt" },
  cache: { category: "cache_or_tlb", description: "MIPS CACHE maintenance" },
  tlbwi: { category: "cache_or_tlb", description: "MIPS TLBWI maintenance" },
  tlbwr: { category: "cache_or_tlb", description: "MIPS TLBWR maintenance" },
  tlbr: { category: "cache_or_tlb", description: "MIPS TLBR maintenance" },
  tlbp: { category: "cache_or_tlb", description: "MIPS TLBP maintenance" },
};

const classifyMips = (
  mnemonic: string,
  operands: readonly string[],
): ClassifiedInstruction | null => {
  if (MIPS_CP0_MOVES.has(mnemonic) && operands.length >= 2) {
    const cp0Reg = operands[1]!.toUpperCase();
    const sel = operands[2] !== undefined ? `,${operands[2]}` : "";
    const target = `CP0:${cp0Reg}${sel}`;
    return {
      mnemonic,
      category: "coprocessor",
      direction: mnemonic.includes("mf") ? "read" : "write",
      target,
      target_description: `MIPS System Control Coprocessor (${target})`,
      target_basis: "architecture_manual",
    };
  }
  if (mnemonic === "ei" || mnemonic === "di") {
    return {
      mnemonic,
      category: "interrupt_mask",
      direction: "read_modify_write",
      target: "CP0:Status.IE",
      target_description:
        mnemonic === "di"
          ? "Disable MIPS Global Interrupts"
          : "Enable MIPS Global Interrupts",
      target_basis: "architecture_manual",
    };
  }
  const fixed = MIPS_FIXED_OPS[mnemonic];
  if (fixed !== undefined) {
    return {
      mnemonic,
      category: fixed.category,
      direction: "control",
      target: null,
      target_description: fixed.description,
      target_basis: "not_applicable",
    };
  }
  return null;
};

const parseInstructionLine = (
  rawLine: string,
): {
  readonly address: string | null;
  readonly mnemonic: string;
  readonly operands: readonly string[];
} | null => {
  const withoutComment = rawLine
    .replace(/(?:;|\/\/|#(?![0-9a-fxA-FX+-])).*$/u, "")
    .trim();
  if (withoutComment.length === 0) return null;

  let address: string | null = null;
  let body = withoutComment;
  const addrMatch =
    /^(?:[a-zA-Z0-9_]+:)?(0x[0-9a-fA-F]+|[0-9a-fA-F]{6,16}):?\s+(.+)$/u.exec(
      withoutComment,
    );
  if (addrMatch !== null) {
    const rawAddr = addrMatch[1]!;
    address =
      rawAddr.startsWith("0x") || rawAddr.startsWith("0X")
        ? `0x${rawAddr.slice(2).toLowerCase()}`
        : `0x${rawAddr.toLowerCase()}`;
    body = addrMatch[2]!.trim();
    const afterBytes =
      /^(?:[0-9a-fA-F]{2,8}\s+)+([a-zA-Z][a-zA-Z0-9._]*\b.*)$/u.exec(body);
    if (afterBytes !== null) {
      body = afterBytes[1]!.trim();
    }
  }

  body = body.replace(/^(?:lock|rep|repe|repz|repne|repnz)\s+/iu, "");
  const spaceIdx = body.search(/\s/u);
  const mnemonic = (
    spaceIdx === -1 ? body : body.slice(0, spaceIdx)
  ).toLowerCase();
  if (mnemonic.length === 0) return null;
  const operandStr = spaceIdx === -1 ? "" : body.slice(spaceIdx + 1).trim();
  const operands =
    operandStr.length === 0
      ? []
      : operandStr
          .split(",")
          .map((tok) => tok.trim())
          .filter((tok) => tok.length > 0);
  return { address, mnemonic, operands };
};

const classifyByArch = (
  arch: HardwareInstructionArchitecture,
  mnemonic: string,
  operands: readonly string[],
): ClassifiedInstruction | null => {
  switch (arch) {
    case "arm":
      return classifyArmOrArm64(mnemonic, operands, false);
    case "arm64":
      return classifyArmOrArm64(mnemonic, operands, true);
    case "riscv":
      return classifyRiscvInstruction(mnemonic, operands);
    case "xtensa":
      return classifyXtensa(mnemonic, operands);
    case "mips":
      return classifyMips(mnemonic, operands);
    case "x86":
    case "x86_64":
      return classifyX86Instruction(mnemonic, operands);
  }
};

/** Extract non-MMIO architectural hardware channels from disassembled instructions. */
export const analyzeProcedureHardwareInstructions = (options: {
  readonly procedure: HardwareInstructionChannelsResult["procedure"];
  readonly architecture: HardwareInstructionArchitecture;
  readonly instructions: readonly string[];
  readonly upstreamLimitations?: readonly string[] | undefined;
}): HardwareInstructionChannelsResult => {
  const { procedure, architecture, instructions, upstreamLimitations } =
    options;
  const channels: HardwareInstructionChannel[] = [];
  const byCategory: Record<string, number> = {};
  const distinctTargets = new Set<string>();
  // not-an-allowance: count of unresolved register-indirect MSR/port sites
  let unresolvedDynamicCount = 0;

  for (let i = 0; i < instructions.length; i += 1) {
    const raw = instructions[i]!;
    const parsed = parseInstructionLine(raw);
    if (parsed === null) continue;
    const hit = classifyByArch(architecture, parsed.mnemonic, parsed.operands);
    if (hit === null) continue;
    byCategory[hit.category] = (byCategory[hit.category] ?? 0) + 1;
    if (hit.target !== null) distinctTargets.add(hit.target);
    if (hit.target_basis === "unresolved_register") unresolvedDynamicCount += 1;
    channels.push({
      instruction_index: i,
      instruction_address: parsed.address,
      raw_instruction: raw,
      mnemonic: hit.mnemonic,
      category: hit.category,
      direction: hit.direction,
      target: hit.target,
      target_description: hit.target_description,
      target_basis: hit.target_basis,
    });
  }

  const limitations = [...(upstreamLimitations ?? [])];
  if (unresolvedDynamicCount > 0) {
    limitations.push(
      `${String(unresolvedDynamicCount)} hardware instruction(s) select their port or register index dynamically through a general-purpose register (such as DX or ECX); use trace_native_values or analyze_function to inspect constant propagation.`,
    );
  }

  return {
    procedure,
    hardware_architecture: architecture,
    examined_instruction_count: instructions.length,
    matched_instruction_count: channels.length,
    channels,
    summary: {
      by_category: byCategory,
      distinct_targets: [...distinctTargets].sort(compareUnicodeCodePoints),
      unresolved_dynamic_count: unresolvedDynamicCount,
    },
    limitations,
  };
};
