//===- LetheObfuscation.cpp - Lethe custom compile-time obfuscator --------===//
//
// Lethe obfuscation pass plugin  --  the "OLLVM but everything custom" layer.
//
// Lethe already PACKS the shipping PE (per-section deflate + AES-256-GCM,
// import elision, anti-debug, anti-dump).  Packing hides the code until it is
// unpacked in RAM.  This plugin attacks the *other* half of the problem: once
// an analyst has unpacked the image, the machine code they recover should have
// no readable structure.  We do that at COMPILE TIME, in LLVM IR, before the
// backend ever emits x64 -- so there is no runtime unpack cost and nothing for
// a dumper to strip.
//
// Why custom instead of stock OLLVM?  Off-the-shelf deobfuscators
// (D-810, SATURN, generic Triton/angr recipes) pattern-match the *known* OLLVM
// transforms.  Every knob here is driven by a PER-BUILD SEED
// (env LETHE_OBF_SEED, or the -lethe-seed pass option), so two builds of the
// same source produce different flattened dispatchers, different opaque
// predicates, different bogus blocks, and a different subset of MBA rewrites.
// A tool tuned to one build does not transfer to the next, and there is no
// public signature for "Lethe flavour" flattening because it is ours.
//
// House rules (mirrored from Lethe's README / daedalus_mba.py):
//   * Correctness is NON-NEGOTIABLE.  Every transform here is semantics-
//     preserving by construction; where a classic textbook trick is only valid
//     over the integers Z (and would *break* under two's-complement wraparound
//     mod 2^n), we deliberately substitute an identity that is exact in
//     Z/2^n and say so at the call site.  See emitOpaqueTrue().
//   * The MBA identities are the same ones daedalus_mba.py PROVES with an
//     oracle:  a^b = (a|b) - (a&b),  a+b = (a^b) + 2*(a&b).
//
// Modern LLVM only:  new PassManager, opaque pointers, PassInfoMixin,
// PreservedAnalyses run(Function&, FunctionAnalysisManager&).
// Targeted at LLVM 17 / 18.  See the API-version caveats in obfuscation/README.md
// and the inline "API NOTE" comments -- these are the exact spots to check when
// you build this on a newer/older LLVM.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h" // PreservedAnalyses, FunctionAnalysisManager,
                                 // createModuleToFunctionPassAdaptor
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h" // DemoteRegToStack / DemotePHIToStack
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

using namespace llvm;

// Windows DLL export: LLVM's PassPlugin loader resolves "llvmGetPassPluginInfo"
// via GetProcAddress, so on Windows the symbol MUST be exported from the DLL.
// LLVM_ATTRIBUTE_WEAK expands to nothing on MSVC, which is fine.
#if defined(_WIN32)
#define LETHE_EXPORT __declspec(dllexport)
#else
#define LETHE_EXPORT
#endif

#define LETHE_DEBUG_TYPE "lethe-obf"

//===----------------------------------------------------------------------===//
// Command-line / environment configuration.
//
// Precedence for every knob:  explicit pass option  >  environment variable  >
// built-in default.  Environment variables are the ergonomic path for a build
// pipeline ("set LETHE_OBF_SEED=%GIT_SHA% & clang-cl ..."); the -mllvm options
// exist for one-off opt(1) experiments.
//===----------------------------------------------------------------------===//

static cl::opt<std::string>
    OptSeed("lethe-seed",
            cl::desc("Per-build obfuscation seed (decimal, 0x-hex, or any "
                     "string -- a non-numeric value is FNV-1a hashed). "
                     "Overrides $LETHE_OBF_SEED."),
            cl::init(""));

static cl::opt<int>
    OptLevel("lethe-obf-level",
             cl::desc("Obfuscation intensity 0..3 (0 = disabled). Overrides "
                      "$LETHE_OBF_LEVEL. Default 1."),
             cl::init(-1)); // -1 == "not set on the command line"

static cl::opt<bool> OptFlatten("lethe-flatten",
                                cl::desc("Enable control-flow flattening."),
                                cl::init(true));
static cl::opt<bool> OptOpaque("lethe-opaque",
                               cl::desc("Enable opaque-predicate insertion."),
                               cl::init(true));
static cl::opt<bool> OptMBA("lethe-mba",
                            cl::desc("Enable MBA arithmetic substitution."),
                            cl::init(true));
static cl::opt<bool> OptBCF("lethe-bcf",
                            cl::desc("Enable bogus control flow / block split."),
                            cl::init(true));

namespace {

// FNV-1a 64 -- the same hash family Lethe's stub uses for import resolution.
// We use it both to fold a build-id string into a numeric seed and to spread
// the global seed per-function so every function gets its own PRNG stream.
static uint64_t fnv1a64(StringRef S) {
  uint64_t H = 1469598103934665603ULL;
  for (unsigned char C : S) {
    H ^= C;
    H *= 1099511628211ULL;
  }
  return H;
}

static uint64_t parseSeed(StringRef S) {
  S = S.trim();
  if (S.empty())
    return 0;
  uint64_t V = 0;
  if (S.starts_with("0x") || S.starts_with("0X")) {
    // getAsInteger returns TRUE on error.
    if (!S.drop_front(2).getAsInteger(16, V))
      return V ? V : 1;
    return fnv1a64(S);
  }
  if (!S.getAsInteger(10, V))
    return V ? V : 1;
  // Non-numeric (e.g. a git commit hash) -> hash it. This is the common
  // pipeline case: LETHE_OBF_SEED=<40-char sha>.
  return fnv1a64(S);
}

struct LetheConfig {
  uint64_t Seed = 0;
  unsigned Level = 1;
  bool Flatten = true;
  bool Opaque = true;
  bool MBA = true;
  bool BCF = true;

  // Built once (thread-safe static init) and cached for the whole process.
  static const LetheConfig &get() {
    static LetheConfig C = build();
    return C;
  }

private:
  static LetheConfig build() {
    LetheConfig C;

    // --- seed -----------------------------------------------------------
    bool HaveSeed = false;
    if (OptSeed.getNumOccurrences() && !OptSeed.getValue().empty()) {
      C.Seed = parseSeed(OptSeed.getValue());
      HaveSeed = C.Seed != 0;
    }
    if (!HaveSeed) {
      if (const char *E = std::getenv("LETHE_OBF_SEED")) {
        C.Seed = parseSeed(StringRef(E));
        HaveSeed = C.Seed != 0;
      }
    }
    if (!HaveSeed) {
      // Deliberate fixed fallback so a build without a seed is still
      // reproducible (never a *random* transform you cannot reproduce for a
      // crash repro). Pipelines SHOULD set LETHE_OBF_SEED per build.
      C.Seed = 0xC0FFEE1234ABCDEFULL;
      errs() << "[lethe-obf] warning: no LETHE_OBF_SEED / -lethe-seed set; "
                "using the fixed fallback seed. Set a per-build seed so each "
                "release differs.\n";
    }

    // --- level ----------------------------------------------------------
    int Lvl = 1;
    if (OptLevel.getNumOccurrences() && OptLevel >= 0)
      Lvl = OptLevel;
    else if (const char *E = std::getenv("LETHE_OBF_LEVEL"))
      Lvl = std::atoi(E);
    if (Lvl < 0)
      Lvl = 0;
    if (Lvl > 3)
      Lvl = 3;
    C.Level = static_cast<unsigned>(Lvl);

    C.Flatten = OptFlatten;
    C.Opaque = OptOpaque;
    C.MBA = OptMBA;
    C.BCF = OptBCF;
    return C;
  }
};

// Clamp a per-transform probability so even level 3 leaves *some* untouched
// instructions (uniform saturation is itself a signature).
static double scaledProb(double perLevel, unsigned level, double cap) {
  double p = perLevel * static_cast<double>(level);
  return p > cap ? cap : p;
}

//===----------------------------------------------------------------------===//
// Opaque-value source.
//
// Two internal, NON-constant i32 globals fed by VOLATILE loads. Volatile is the
// load-bearing detail: it forbids the optimizer from assuming the stored value,
// so GlobalOpt cannot constant-propagate the initializer and fold our
// predicates away. A bogus block also volatile-STORES to one of them, which
// further poisons any "this global is never written" analysis.
//===----------------------------------------------------------------------===//

static GlobalVariable *getOpaqueGlobal(Module &M, std::mt19937_64 &RNG) {
  const char *Name = "__lethe_opaque_state";
  if (GlobalVariable *G = M.getGlobalVariable(Name, /*AllowInternal=*/true))
    return G;
  IntegerType *I32 = Type::getInt32Ty(M.getContext());
  Constant *Init = ConstantInt::get(I32, static_cast<uint32_t>(RNG() | 1u));
  auto *G = new GlobalVariable(M, I32, /*isConstant=*/false,
                               GlobalValue::InternalLinkage, Init, Name);
  G->setAlignment(Align(4));
  return G;
}

// Build an i1 that is ALWAYS TRUE at runtime but opaque to the optimizer/solver.
//
// IMPORTANT CORRECTNESS NOTE: the classic textbook predicate 7*y*y - 1 != x*x
// (and cousins like x*x != 3*y*y) are only guaranteed over the INTEGERS Z. Under
// two's-complement wraparound mod 2^n they can become FALSE for some x,y, which
// would divert real control flow into a bogus block -> miscompile. So we do NOT
// use them. Instead we use low-bit *parity* invariants that are exact for ALL
// values in Z/2^n:
//     x*(x+1)  is even           -> product of consecutive integers
//     x*x + x  is even           -> == x*(x+1)
//     x | (x+1) is odd           -> consecutive ints, one is odd
// Each holds bit-for-bit under modular arithmetic, so the predicate is TRUE for
// every possible runtime value of the volatile-loaded x.
static Value *emitOpaqueTrue(IRBuilder<> &B, GlobalVariable *G,
                             std::mt19937_64 &RNG) {
  LoadInst *X = B.CreateLoad(B.getInt32Ty(), G, /*isVolatile=*/true, "lethe.op");
  Value *One = B.getInt32(1);
  Value *Zero = B.getInt32(0);
  switch (RNG() % 3) {
  case 0: { // (x*(x+1) & 1) == 0
    Value *T = B.CreateMul(X, B.CreateAdd(X, One));
    return B.CreateICmpEQ(B.CreateAnd(T, One), Zero);
  }
  case 1: { // ((x*x + x) & 1) == 0
    Value *T = B.CreateAdd(B.CreateMul(X, X), X);
    return B.CreateICmpEQ(B.CreateAnd(T, One), Zero);
  }
  default: { // ((x | (x+1)) & 1) == 1
    Value *T = B.CreateOr(X, B.CreateAdd(X, One));
    return B.CreateICmpEQ(B.CreateAnd(T, One), One);
  }
  }
}

// A never-executed junk block that unconditionally branches to Target. Because
// it is guarded by an always-true opaque predicate it is dead at runtime, so its
// contents cannot affect behaviour; we only require WELL-FORMED IR. It uses
// nothing but fresh constants and a volatile load/store of the opaque global, so
// there are no dominance hazards. Any PHIs in Target get an undef incoming for
// this new predecessor edge -- correct precisely because the edge never fires.
static BasicBlock *makeBogusBlock(Function &F, BasicBlock *Target,
                                  GlobalVariable *G, std::mt19937_64 &RNG) {
  LLVMContext &Ctx = F.getContext();
  BasicBlock *BB = BasicBlock::Create(Ctx, "lethe.bogus", &F);
  IRBuilder<> B(BB);
  LoadInst *X = B.CreateLoad(B.getInt32Ty(), G, /*isVolatile=*/true);
  Value *J = B.CreateMul(X, B.getInt32(static_cast<uint32_t>(RNG() | 1u)));
  J = B.CreateXor(J, B.getInt32(static_cast<uint32_t>(RNG())));
  B.CreateStore(J, G)->setVolatile(true);
  B.CreateBr(Target);
  for (PHINode &Phi : Target->phis())
    Phi.addIncoming(UndefValue::get(Phi.getType()), BB);
  return BB;
}

static bool isLetheScaffold(const BasicBlock &BB) {
  return BB.getName().starts_with("lethe.");
}

//===----------------------------------------------------------------------===//
// (c) MBA substitution.
//
// Rewrite integer Add/Sub/And/Or/Xor into mixed boolean-arithmetic identities
// that are EXACT in Z/2^n (the same identities daedalus_mba.py proves with its
// oracle). We snapshot the candidate binops first and only rewrite that
// snapshot, so the freshly-created MBA instructions are never re-expanded
// (no unbounded growth).
//===----------------------------------------------------------------------===//

static bool substituteMBA(Function &F, std::mt19937_64 &RNG, unsigned Level) {
  const double Prob = scaledProb(0.35, Level, 0.9);
  std::uniform_real_distribution<double> Chance(0.0, 1.0);

  SmallVector<BinaryOperator *, 32> Work;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      auto *BO = dyn_cast<BinaryOperator>(&I);
      if (!BO)
        continue;
      auto *Ty = dyn_cast<IntegerType>(BO->getType());
      if (!Ty || Ty->getBitWidth() < 2) // i1 is pointless / degenerate here
        continue;
      switch (BO->getOpcode()) {
      case Instruction::Add:
      case Instruction::Sub:
      case Instruction::And:
      case Instruction::Or:
      case Instruction::Xor:
        Work.push_back(BO);
        break;
      default:
        break;
      }
    }
  }

  bool Changed = false;
  for (BinaryOperator *BO : Work) {
    if (Chance(RNG) > Prob)
      continue;
    IRBuilder<> B(BO);
    Value *A = BO->getOperand(0);
    Value *C = BO->getOperand(1);
    Value *NV = nullptr;
    switch (BO->getOpcode()) {
    case Instruction::Add: // a + b = (a^b) + 2*(a&b)
      NV = B.CreateAdd(B.CreateXor(A, C), B.CreateShl(B.CreateAnd(A, C), 1));
      break;
    case Instruction::Sub: // a - b = (a^b) - 2*(~a & b)
      NV = B.CreateSub(B.CreateXor(A, C),
                       B.CreateShl(B.CreateAnd(B.CreateNot(A), C), 1));
      break;
    case Instruction::Xor: // a ^ b = (a|b) - (a&b)
      NV = B.CreateSub(B.CreateOr(A, C), B.CreateAnd(A, C));
      break;
    case Instruction::And: // a & b = (a|b) - (a^b)
      NV = B.CreateSub(B.CreateOr(A, C), B.CreateXor(A, C));
      break;
    case Instruction::Or: // a | b = (a&b) + (a^b)
      NV = B.CreateAdd(B.CreateAnd(A, C), B.CreateXor(A, C));
      break;
    default:
      break;
    }
    if (NV) {
      // Note: we intentionally drop nsw/nuw poison flags -- the expansion uses
      // plain wrapping arithmetic, which is always valid even when the original
      // op promised no-wrap.
      BO->replaceAllUsesWith(NV);
      BO->eraseFromParent();
      Changed = true;
    }
  }
  return Changed;
}

//===----------------------------------------------------------------------===//
// (b) Opaque predicates.
//
// Replace some unconditional branches `br Dest` with `br OPAQUE_TRUE, Dest,
// Bogus`. Runtime always takes Dest; the solver cannot prove that, so Bogus
// looks live and pollutes every reachability/def-use analysis.
//===----------------------------------------------------------------------===//

static bool insertOpaquePredicates(Function &F, GlobalVariable *G,
                                   std::mt19937_64 &RNG, unsigned Level) {
  const double Prob = scaledProb(0.25, Level, 0.85);
  std::uniform_real_distribution<double> Chance(0.0, 1.0);

  SmallVector<BranchInst *, 32> Uncond;
  for (BasicBlock &BB : F) {
    if (isLetheScaffold(BB))
      continue;
    auto *Br = dyn_cast<BranchInst>(BB.getTerminator());
    if (Br && Br->isUnconditional())
      Uncond.push_back(Br);
  }

  bool Changed = false;
  for (BranchInst *Br : Uncond) {
    if (Chance(RNG) > Prob)
      continue;
    BasicBlock *Dest = Br->getSuccessor(0);
    IRBuilder<> B(Br);
    Value *Pred = emitOpaqueTrue(B, G, RNG);
    BasicBlock *Bogus = makeBogusBlock(F, Dest, G, RNG);
    B.CreateCondBr(Pred, Dest, Bogus);
    Br->eraseFromParent();
    Changed = true;
  }
  return Changed;
}

//===----------------------------------------------------------------------===//
// (d) Bogus control flow / basic-block splitting.
//
// Split a block in two, then guard the tail behind an opaque-true predicate with
// a bogus alternate path. The split multiplies the number of blocks (great fuel
// for the flattener that runs afterwards) and the guard makes the trivial fall-
// through look like a real decision.
//===----------------------------------------------------------------------===//

static bool bogusControlFlow(Function &F, GlobalVariable *G,
                             std::mt19937_64 &RNG, unsigned Level) {
  const double Prob = scaledProb(0.30, Level, 0.85);
  std::uniform_real_distribution<double> Chance(0.0, 1.0);

  // Snapshot the blocks that exist *now*; we skip our own scaffold and any EH
  // machinery so we never split something that must stay intact.
  SmallVector<BasicBlock *, 32> Blocks;
  for (BasicBlock &BB : F) {
    if (isLetheScaffold(BB))
      continue;
    if (BB.isEHPad() || BB.isLandingPad())
      continue;
    if (isa<InvokeInst>(BB.getTerminator()) ||
        isa<CallBrInst>(BB.getTerminator()))
      continue;
    Blocks.push_back(&BB);
  }

  bool Changed = false;
  for (BasicBlock *BB : Blocks) {
    if (Chance(RNG) > Prob)
      continue;

    // Choose a split point strictly between the PHIs and the terminator, and
    // never at an instruction that must lead its block (PHIs, EH pads).
    SmallVector<Instruction *, 16> Points;
    Instruction *Term = BB->getTerminator();
    for (Instruction &I : *BB) {
      if (isa<PHINode>(&I) || &I == Term || I.isEHPad())
        continue;
      Points.push_back(&I);
    }
    if (Points.empty())
      continue;

    Instruction *SplitPt = Points[RNG() % Points.size()];
    // splitBasicBlock puts [SplitPt .. end] into Tail and leaves BB ending in an
    // unconditional branch to Tail. Splitting past all PHIs guarantees Tail has
    // no PHIs, so adding a bogus predecessor to it is trivially safe.
    BasicBlock *Tail = BB->splitBasicBlock(SplitPt->getIterator(), "lethe.tail");

    Instruction *Uncond = BB->getTerminator(); // the auto-inserted br Tail
    IRBuilder<> B(Uncond);
    Value *Pred = emitOpaqueTrue(B, G, RNG);
    BasicBlock *Bogus = makeBogusBlock(F, Tail, G, RNG);
    B.CreateCondBr(Pred, Tail, Bogus);
    Uncond->eraseFromParent();
    Changed = true;
  }
  return Changed;
}

//===----------------------------------------------------------------------===//
// (a) Control-flow flattening.
//
// Collapse the CFG into a dispatcher loop:
//
//     entry:  state = C0;  br loopEntry
//     loopEntry:  s = load state;  switch s [ Ci -> Bi ... ] default swDefault
//     Bi:  <original body>;  state = C(succ);  br loopEnd        (1 successor)
//          <original body>;  state = sel(cond,Ct,Cf); br loopEnd (2 successors)
//          <original body>;  ret / unreachable                   (0 successors)
//     loopEnd:  br loopEntry
//     swDefault:  br loopEnd
//
// Case constants are per-build random, so no two builds share a dispatcher.
//
// This is the well-known OLLVM construction, re-implemented for the new
// PassManager / opaque pointers. The subtle correctness point: flattening
// destroys the natural dominance between blocks (every Bi is now reached only
// via the dispatcher), so any SSA value defined in one block and used in another
// -- and every PHI -- must be demoted to a stack slot afterwards. fixStack()
// does exactly that via LLVM's Demote{Reg,PHI}ToStack utilities.
//===----------------------------------------------------------------------===//

// Demote cross-block SSA values and all PHIs to stack slots so the flattened
// CFG type-checks and preserves semantics. Loops until a fixed point because a
// demotion can expose freshly-cross-block loads (it never does in practice, but
// the loop is cheap insurance and matches OLLVM's fixStack).
static void fixStack(Function &F) {
  std::vector<PHINode *> Phis;
  std::vector<Instruction *> Regs;
  bool Again = true;
  while (Again) {
    Phis.clear();
    Regs.clear();
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *P = dyn_cast<PHINode>(&I)) {
          Phis.push_back(P);
        } else if (!isa<AllocaInst>(&I) && I.isUsedOutsideOfBlock(&BB)) {
          // Entry-block allocas still dominate everything after flattening, so
          // they never need demotion; skipping them avoids pointless slots.
          Regs.push_back(&I);
        }
      }
    }
    for (PHINode *P : Phis)
      DemotePHIToStack(P);
    for (Instruction *I : Regs)
      DemoteRegToStack(*I);
    Again = !Phis.empty() || !Regs.empty();
  }
}

static bool flattenFunction(Function &F, std::mt19937_64 &RNG) {
  if (F.isDeclaration())
    return false;

  // Bail out (leave the function untouched) on anything the simple switch
  // dispatcher cannot faithfully reproduce. Correctness first; coverage second.
  for (BasicBlock &BB : F) {
    if (BB.isEHPad() || BB.hasAddressTaken())
      return false;
    Instruction *T = BB.getTerminator();
    if (isa<InvokeInst>(T) || isa<IndirectBrInst>(T) || isa<CallBrInst>(T) ||
        isa<SwitchInst>(T) || isa<ResumeInst>(T) || isa<CatchSwitchInst>(T) ||
        isa<CatchReturnInst>(T) || isa<CleanupReturnInst>(T))
      return false;
  }

  Module *M = F.getParent();
  LLVMContext &Ctx = F.getContext();
  IntegerType *I32 = Type::getInt32Ty(Ctx);
  const unsigned AllocaAS = M->getDataLayout().getAllocaAddrSpace();

  // Every block except the entry becomes a switch case.
  std::vector<BasicBlock *> OrigBB;
  for (BasicBlock &BB : F)
    OrigBB.push_back(&BB);
  if (OrigBB.size() <= 1)
    return false;
  OrigBB.erase(OrigBB.begin()); // drop the entry

  BasicBlock *PreHeader = &F.getEntryBlock();
  Instruction *EntryTerm = PreHeader->getTerminator();
  if (EntryTerm->getNumSuccessors() == 0)
    return false; // entry just returns -- nothing to dispatch

  // If the entry ends in a conditional branch, peel the branch off into its own
  // block so the pre-header ends cleanly with a single edge. Splitting exactly
  // at the terminator leaves the (cross-block) condition value in the pre-header
  // -- fixStack() will demote it.
  if (auto *Br = dyn_cast<BranchInst>(EntryTerm)) {
    if (Br->isConditional()) {
      BasicBlock *NB =
          PreHeader->splitBasicBlock(Br->getIterator(), "lethe.first");
      OrigBB.insert(OrigBB.begin(), NB);
    }
  }

  // The single successor of the (now unconditional) pre-header terminator is the
  // first block the dispatcher must jump to.
  BasicBlock *FirstReal = PreHeader->getTerminator()->getSuccessor(0);

  // Assign each case a unique, per-build-random 32-bit constant.
  DenseMap<BasicBlock *, ConstantInt *> CaseOf;
  std::unordered_set<uint32_t> Used;
  for (BasicBlock *BB : OrigBB) {
    uint32_t V;
    do {
      V = static_cast<uint32_t>(RNG());
    } while (V == 0 || Used.count(V));
    Used.insert(V);
    CaseOf[BB] = ConstantInt::get(I32, V);
  }

  // Replace the pre-header terminator with: alloca state; state = C(FirstReal).
  PreHeader->getTerminator()->eraseFromParent();
  auto *StateVar = new AllocaInst(I32, AllocaAS, "lethe.state", PreHeader);
  new StoreInst(CaseOf[FirstReal], StateVar, PreHeader);

  // Dispatcher scaffold.
  BasicBlock *LoopEntry = BasicBlock::Create(Ctx, "lethe.dispatch", &F);
  BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "lethe.backedge", &F);
  BasicBlock *SwDefault = BasicBlock::Create(Ctx, "lethe.default", &F);

  auto *Load = new LoadInst(I32, StateVar, "lethe.s", LoopEntry);
  SwitchInst *Switch =
      SwitchInst::Create(Load, SwDefault, OrigBB.size(), LoopEntry);

  BranchInst::Create(LoopEntry, PreHeader); // pre-header -> dispatcher
  BranchInst::Create(LoopEntry, LoopEnd);   // back edge
  BranchInst::Create(LoopEnd, SwDefault);   // default is unreachable at runtime

  for (BasicBlock *BB : OrigBB)
    Switch->addCase(CaseOf[BB], BB);

  // Rewire each original block's exit to update `state` and loop back.
  for (BasicBlock *BB : OrigBB) {
    Instruction *T = BB->getTerminator();
    unsigned NSucc = T->getNumSuccessors();

    if (NSucc == 0) // ret / unreachable -- leave it, it exits the function
      continue;

    if (NSucc == 1) {
      BasicBlock *Succ = T->getSuccessor(0);
      IRBuilder<> B(T);
      B.CreateStore(CaseOf.lookup(Succ), StateVar);
      B.CreateBr(LoopEnd);
      T->eraseFromParent();
      continue;
    }

    if (NSucc == 2) {
      auto *Br = cast<BranchInst>(T); // only conditional branches reach here
      ConstantInt *CT = CaseOf.lookup(Br->getSuccessor(0));
      ConstantInt *CF = CaseOf.lookup(Br->getSuccessor(1));
      IRBuilder<> B(T);
      // Pick the next state with the ORIGINAL condition -> behaviour preserved.
      Value *Sel = B.CreateSelect(Br->getCondition(), CT, CF);
      B.CreateStore(Sel, StateVar);
      B.CreateBr(LoopEnd);
      T->eraseFromParent();
      continue;
    }
    // NSucc > 2 cannot occur: SwitchInst was rejected in the bail-out scan.
  }

  fixStack(F);
  return true;
}

//===----------------------------------------------------------------------===//
// The pass itself. One FunctionPass drives all four transforms in the order
// that composes correctly: tangle arithmetic first, then multiply/guard the
// CFG, then flatten LAST so it swallows every block the earlier steps produced.
//===----------------------------------------------------------------------===//

struct LetheObfuscationPass : PassInfoMixin<LetheObfuscationPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration() || F.hasFnAttribute(Attribute::OptimizeNone))
      return PreservedAnalyses::all();

    const LetheConfig &Cfg = LetheConfig::get();
    if (Cfg.Level == 0)
      return PreservedAnalyses::all();

    // Per-function PRNG: same global seed, but spread by the function name so
    // each function is obfuscated differently yet the whole build is
    // reproducible from LETHE_OBF_SEED alone.
    std::mt19937_64 RNG(Cfg.Seed ^ fnv1a64(F.getName()));

    GlobalVariable *G = getOpaqueGlobal(*F.getParent(), RNG);

    bool Changed = false;
    if (Cfg.MBA)
      Changed |= substituteMBA(F, RNG, Cfg.Level);
    if (Cfg.Opaque)
      Changed |= insertOpaquePredicates(F, G, RNG, Cfg.Level);
    if (Cfg.BCF)
      Changed |= bogusControlFlow(F, G, RNG, Cfg.Level);
    if (Cfg.Flatten)
      Changed |= flattenFunction(F, RNG);

    // We rewrote the CFG and SSA form wholesale; invalidate everything.
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  // Run even under -O0 / when marked "required" so -fpass-plugin auto-insertion
  // is honoured; per-function opt-out is handled inside run() (OptimizeNone).
  static bool isRequired() { return true; }
};

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Plugin registration (new PassManager).
//===----------------------------------------------------------------------===//

static llvm::PassPluginLibraryInfo getLethePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LetheObfuscation", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // 1) Invoke explicitly by name, e.g.
            //    opt -load-pass-plugin=LetheObfuscation.dll \
            //        -passes='function(lethe-obf)' in.ll
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) -> bool {
                  if (Name == "lethe-obf") {
                    FPM.addPass(LetheObfuscationPass());
                    return true;
                  }
                  return false;
                });

            // 2) Run automatically at the very end of the optimization
            //    pipeline (works with clang's -fpass-plugin). Late is the right
            //    place: it lets the optimizer clean up first and keeps the
            //    flattener's opaque predicates from being simplified away.
            //
            // API NOTE: in LLVM 17/18 the OptimizerLast callback is
            //   void(ModulePassManager&, OptimizationLevel).
            // In LLVM >= 20 it gained a 3rd arg (ThinOrFullLTOPhase); if you
            // build there, add `ThinOrFullLTOPhase` to this lambda's params.
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  // O0 is the only level with speedup level 0; comparing the
                  // level scalar avoids depending on OptimizationLevel::operator==.
                  if (Level.getSpeedupLevel() == 0)
                    return; // don't silently transform unoptimized debug builds
                  MPM.addPass(createModuleToFunctionPassAdaptor(
                      LetheObfuscationPass()));
                });
          }};
}

// The entry point LLVM's plugin loader looks for. Must be exported on Windows.
extern "C" LETHE_EXPORT LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getLethePluginInfo();
}
