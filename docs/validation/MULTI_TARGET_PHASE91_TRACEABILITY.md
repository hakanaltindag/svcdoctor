# Multi-target Phase 9.1 — contract traceability

Every requirement Phase 9.0 froze, mapped to the code that implements it and the tests that
prove it. Built in Phase 9.1C; the requirements are
[`MULTI_TARGET_PHASE90_CONTRACT_STUDY.md`](MULTI_TARGET_PHASE90_CONTRACT_STUDY.md) §6, and the
decisions behind them are ADRs [0071](../decisions/0071-multi-target-configuration-schema.md)
to [0074](../decisions/0074-multi-target-report-and-exit-semantics.md).

## 1. Reconciliation

| | Count |
|---|---|
| Frozen requirements | **108** |
| Proven by a named executable test | **108** |
| Merged into a shared executable proof | 24 |
| Superseded by a stronger test, original identifier retained | 3 |
| **Missing** | **0** |

The 108 are `MT-C01`–`C31` (31), `MT-E01`–`E22` (22), `MT-S01`–`S20` (20), `MT-D01`–`D08` (8),
`MT-R01`–`R18` (18) and `MT-G01`–`G09` (9). Phase 9.1C's brief named only C, E, S and D; the
G and R families are in the same frozen matrix and are reconciled here too.

**No requirement is marked PROVEN because similar behaviour exists.** Each row names a test
function that fails if the requirement stops holding, and the mutation column names the
planted defect that was measured to make it fail.

### 1.1 Identifier drift, and its correction

Phases 9.1A and 9.1B embedded MT identifiers in test names, and **both renumbered as they
went**. By the end of 9.1B a test called `TestMTC05...` proved frozen `MT-C18`, `TestMTE07...`
proved frozen `MT-E08`, and frozen `MT-E07` — the second-interrupt contract — had no test at
all while its number was in use by something else.

That is worse than having no identifiers: a reader checking coverage by grepping for `MTC05`
would find a passing test and move on. Phase 9.1C renumbered every drifted test to the frozen
identifier. Twenty-eight test functions were renamed; no assertion changed.

Three requirements' original identifiers survive only here, because a later test subsumed
them:

| Frozen | Superseded by | Why |
|---|---|---|
| MT-E11 (`concurrency: 1`) | `TestMTE11AndE12ConcurrencyIsBoundedAtEveryPoolSize` | The 9.1B test asserted the pool is at most 1; the 9.1C test asserts the peak **equals** the configured width at 1, 2, 4, 8 and 16, using a barrier |
| MT-E19 (partial report kept on step-budget expiry) | `TestMTE03LocalTimeoutIsCompletedAndIncomplete` | One scenario proves both: the target is COMPLETED, its report survives, and `Incomplete` is true |
| MT-D04 (target identifiers stable) | `TestMTD05AndD07RepeatedRunsAreStable` | Whole-document comparison over 100 runs subsumes the identifier-only assertion |

## 2. Configuration — MT-C01 to MT-C31

Owner: `internal/fleet/config`. Tests: `internal/fleet/config/*_test.go` unless noted.

| ID | Requirement | Test | Mutation |
|---|---|---|---|
| C01 | A valid file covering all four services | `TestMTC01AValidFourServiceFileLoads` | — |
| C02 | Duplicate target ID, both occurrences named | `TestMTC02DuplicateTargetID` | 9.1A A01 |
| C03 | Unknown service type | `TestMTC03UnknownServiceType` | — |
| C04 | Unknown field at the top level | `TestMTC04AndC05UnknownFieldIsRejectedAtEveryLevel` | **C02** |
| C05 | Unknown field inside a service's `config:` | `TestMTC04AndC05UnknownFieldIsRejectedAtEveryLevel` | **C02** |
| C06 | `password: hunter2` rejected | `TestMTC06AndS08APlaintextPasswordIsRefusedStructurally` | **C01** |
| C07 | `password: {env: A, file: B}` rejected | `TestMTC07BothSourcesAreRefused` | — |
| C08 | `password: {}` rejected | `TestMTC08NeitherSourceIsRefused` | — |
| C09 | Missing environment variable | `TestMTC09ToC12PreflightRefusals` | — |
| C10 | Empty environment variable | `TestMTC09ToC12PreflightRefusals` | — |
| C11 | Unreadable secret file | `TestMTC09ToC12PreflightRefusals`, `TestFileTOCTOUPermissionRemoved` | — |
| C12 | Secret file is a directory | `TestMTC09ToC12PreflightRefusals` | — |
| C13 | Malformed YAML — tab indentation | `TestMTC13MalformedYAML` | — |
| C14 | Duplicate YAML key | `TestMTC14DuplicateYAMLKeyIsRejectedAtEveryLevel` | — |
| C15 | `version` absent | `TestMTC15AndC16ConfigVersion` | 9.1A A05 |
| C16 | Unsupported `version` | `TestMTC15AndC16ConfigVersion` | — |
| C17 | Anchor and alias refused | `TestMTC17AnchorAndAliasPolicy` | — |
| C18 | Merge key `<<` refused | `TestMTC18MergeKeyIsRejected` | **C03** |
| C19 | Non-core YAML tag refused | `TestMTC19CustomTagIsRejected` | — |
| C20 | Multi-document file refused | `TestMTC20OnlyOneDocumentIsAccepted` | **C04** |
| C21 | Config file is not a regular file | `TestMTC21TheConfigFileMustBeARegularFile` | — |
| C22 | Config file above 1 MiB | `TestMTC22ConfigByteBound` | — |
| C23 | More than 512 targets | `TestMTC23AndC30TargetCountBounds`, `TestTheTargetMaximumIsRefusedBeforeAnythingExecutes` | — |
| C24 | Target ID grammar | `TestMTC24TargetIDGrammar`, `TestAnUppercaseIdentifierIsRefusedRatherThanFolded` | — |
| C25 | `${DB_HOST}` taken literally | `TestMTC25AndS09ArbitraryInterpolationIsAbsentEverywhere` | — |
| C26 | `run.timeout` below the largest target timeout | `TestRunSectionValidation`, `TestCLIOverridePrecedence` | — |
| C27 | RabbitMQ `step_timeout` ≤ 3 s refused | `TestRabbitMQStepTimeoutFloor` | — |
| C28 | TLS-only fields under `mode: disable` refused | `TestGenericFieldValidation` | — |
| C29 | Missing required service field | `TestPostgresRequiresAnIdentity`, `TestKafkaRequiresAMechanism` | — |
| C30 | Zero targets | `TestMTC23AndC30TargetCountBounds` | — |
| C31 | `--config -` is not stdin | `TestTheRunCommandRefusesConfigStdin` (`internal/cli`) | — |

**Added in 9.1C.** A hostile corpus of 38 documents plus three resource-shaped cases —
`TestTheHostileCorpusNeverEscapesTheConfigBoundary`, `TestPathologicalNestingIsBoundedRatherThanFatal`
— asserting four properties over every one: no panic, a classified `config.Error` or a valid
`Config`, no library-interpolated value in the message, and no network. Four fuzz targets:
`FuzzLoad`, `FuzzServiceNode`, `FuzzCredentialReference`, `FuzzSanitizedErrorPath`.

## 3. Execution — MT-E01 to MT-E22

Owner: `internal/fleet/run`. Tests: `internal/fleet/run/*_test.go` unless noted.

| ID | Requirement | Test | Mutation |
|---|---|---|---|
| E01 | All four targets complete | `TestMTE01AllTargetsComplete` | — |
| E02 | One remote authentication failure; others still run | `TestMTE02RemoteAuthFailureIsACompletedExecution`, `TestMTE02NoFailFastOnDiagnosticOrExecutionFailure` | **C18**, **C30**, **C31** |
| E03 | One local step-budget expiry | `TestMTE03LocalTimeoutIsCompletedAndIncomplete` | — |
| E04 | Credential resolution fails at execution time | `TestMTE04CredentialResolutionFailure`, `TestMTE04EnvTOCTOU`, `TestMTE04FileTOCTOUDeleted` | **C19** |
| E05 | Run budget exhausted before every target starts | `TestMTE05RunBudgetExhaustedBeforeAllTargetsStart` | — |
| E06 | Cancellation with completed, in-flight and queued targets | `TestMTE06CancellationLifecycleMatrix`, `TestMTE06CancellationWithCompletedActiveAndQueued`, `TestCancellationAtEveryPointInTheLifecycle` | **C20**, **C29** |
| E07 | Second interrupt aborts | `TestMTE07AFirstInterruptCancelsAndASecondAborts` (`internal/cli`) | **CEX5** |
| E08 | Output unchanged when completion order changes | `TestMTE08AndD02CompletionOrderNeverReachesTheReport`, `TestMTD02RandomizedCompletionOrderNeverReachesTheOutput` | **C24** |
| E09 | Duplicate endpoints as distinct logical targets | `TestMTE09TheSameEndpointWithDifferentAuthorityIsTwoTargets`, `TestMTE09DuplicateEndpointsAreDistinctExecutions`, `TestSameEndpointDifferentAuthorityThroughRealFixtures` | **C17** |
| E10 | One secret reference used independently by two targets | `TestMTE10SameReferenceResolvesIndependently`, `TestMTS05OneReferenceProducesTwoIndependentCredentials` | **C15** |
| E11 | `concurrency: 1` | `TestMTE11AndE13AndE14Concurrency`, `TestConcurrencyOneMatchesTheSequentialReference` | **C25** |
| E12 | `concurrency: 16` | `TestMTE12MaxConcurrencyIsObserved`, `TestMTE11AndE12ConcurrencyIsBoundedAtEveryPoolSize` | **C25** |
| E13 | `concurrency: 0` rejected | `TestMTE11AndE13AndE14Concurrency` | — |
| E14 | `concurrency: 17` rejected | `TestMTE11AndE13AndE14Concurrency` | **C26** |
| E15 | `--concurrency` overrides the config | `TestCLIOverridePrecedence` (`internal/cli`) | — |
| E16 | `--timeout` overrides the config | `TestCLIOverridePrecedence` (`internal/cli`) | — |
| E17 | A target budget cannot exceed the remaining run budget | `TestMTE17RunDeadlineDominatesTargetDeadline`, `TestMTE17DeadlineRaceStress` | **C27** |
| E18 | No credential ⇒ `CREDENTIAL_NOT_CONFIGURED`, exit 0 | `TestAMissingCredentialIsNotAnAuthenticationFailure` (integration) | — |
| E19 | Partial report preserved when the step budget expires | `TestMTE03LocalTimeoutIsCompletedAndIncomplete` | — |
| E20 | No target dialled when any configuration error exists | `TestMTE20AConfigurationErrorDialsNothing` (`internal/cli`) | **C38** |
| E21 | No goroutine or worker leak after cancellation | `TestNoGoroutineIsLeakedAfterCancellation`, `TestNoGoroutineIsLeakedAcrossRepeatedRuns` | — |
| E22 | 512 targets complete | `TestMTE22TheTargetMaximumExecutes` | — |

**Added in 9.1C.** `TestAPreCancelledRunTouchesNothing` and the structural
`TestTheSchedulerChecksTheRunContextBeforeSpendingAnything` (`test/security`), which together
own the race window where a target is offered as the run ends. `TestMTE16ATargetTimeoutDoesNotCancelASibling`
was rewritten to hold the siblings in flight — see §7.

## 4. Security — MT-S01 to MT-S20

| ID | Requirement | Test | Mutation |
|---|---|---|---|
| S01 | No secret value in terminal output | `TestMTS01ToS04NoSecretReachesAnyRunSurface`, `TestMTS01ToS04TheAdversarialSecretCorpusNeverEscapes` | **C12** |
| S02 | No secret value in JSON output | same | **C11** |
| S03 | No secret value in shareable output | same | **C11** |
| S04 | No secret value on any error path | `TestMTS04NoSecretValueReachesAnError`, `assertNoCanary` across the TOCTOU suite | **C09** |
| S05 | Two targets, one reference, distinct credentials | `TestMTS05OneReferenceProducesTwoIndependentCredentials`, `TestMTS05SameReferenceResolvesIndependently`, `TestOneFileReferenceProducesTwoReads` | **C14**, **C15** |
| S06 | No `security.Reveal` in any fleet package | `TestTheFleetLayerNeverRevealsASecret` | **C36** |
| S07 | Runner core imports no adapter/wire/diagnosis/probe/render | `TestTheFleetCoreReachesNoProtocol`, `TestNoRunSurfaceComparesTwoTargetReports` | **C34**, **C35** |
| S08 | A plaintext config secret is structurally rejected | `TestMTC06AndS08APlaintextPasswordIsRefusedStructurally` | **C01** |
| S09 | Arbitrary environment interpolation is rejected | `TestMTC25AndS09ArbitraryInterpolationIsAbsentEverywhere` | — |
| S10 | The raw configuration is never serialized | `TestAValidatedConfigRetainsNoRawBytes`, `TestTheAggregateSerializesNoConfigurationSurface` | **C05**, **C40** |
| S11 | Credential reference names and paths never reach a report | `TestMTS11NoCredentialReferenceReachesTheReport`, `TestMTS11AndS12NoCredentialSourceMetadataReachesTheAggregate`, `TestAnExecutionErrorMessageNamesNoCredentialReference` | **C06**, **C07**, **C08**, **C10** |
| S12 | The config file path never reaches a report | `TestMTS11AndS12NoCredentialSourceMetadataReachesTheAggregate` | — |
| S13 | `internal/fleet/config` does not import `internal/security` | `TestTheConfigPackageCannotConstructASecret` | — |
| S14 | `internal/cli` has zero environment-read call sites | `TestTheCLIStillReadsNoEnvironmentVariable` | — |
| S15 | Target IDs are pseudonymized under `--shareable` | `TestMTS15ShareableNeverExposesWhatLocalAlreadyHid`, `TestMTS16OnePseudonymTablePerRun` | — |
| S16 | One host in two targets receives one pseudonym | `TestMTS16OnePseudonymTablePerRun`, `TestManyDistinctIdentitiesReceiveDistinctPseudonyms` | **C39** |
| S17 | A credential bound to the wrong endpoint is refused | `assertOpensOnlyAt` in `TestMTS05OneReferenceProducesTwoIndependentCredentials` and `TestMTE09TheSameEndpointWithDifferentAuthorityIsTwoTargets` | **C16** |
| S18 | No `%v` / `%+v` / `%#v` of a credential-bearing structure | `TestReferenceFormattingCannotLeak`, `TestTheSafeMessageIsAlsoSafeUnderEveryFormattingVerb` | **C13** |
| S19 | `run` exposes no `--password-*` flag | `TestTheRunCommandExposesOnlyRunGlobalFlags` | **CEX4** |
| S20 | Preflight retains no secret value | `TestMTS20PreflightRetainsNoSecretValue` | **C11** |

**Added in 9.1C.** A 25-value adversarial secret corpus searched in three representations
(raw, JSON-escaped, quoted) across four invocations; source-metadata absence for the
environment variable name, the credential file path, the configuration path and three Go type
names; and `TestASecretEqualToAReportedValueIsIndistinguishable`, which states the one limit
this cannot remove — see §8.

## 5. Determinism — MT-D01 to MT-D08

| ID | Requirement | Test | Mutation |
|---|---|---|---|
| D01 | Declared configuration order preserved | `TestMTD01DeclaredOrderIsPreservedThroughExecution`, `TestDeclaredOrderSurvivesMixedExecutionStates`, `TestDeclaredOrderIsPreservedByTheLoader`, `TestTheAggregateNeverReordersItsTargets` | **C23**, **C24** |
| D02 | Worker completion order does not reach the output | `TestMTE08AndD02CompletionOrderNeverReachesTheReport`, `TestMTD02RandomizedCompletionOrderNeverReachesTheOutput` | **C24** |
| D03 | Findings within a target match the single-target run exactly | `TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun` | — |
| D04 | Target IDs are stable | `TestMTD05AndD07RepeatedRunsAreStable` | — |
| D05 | The aggregate summary is stable | `TestMTD05AndD07RepeatedRunsAreStable`, `TestRepeatedRunsAreStructurallyIdentical` | — |
| D06 | No map iteration decides any order in the fleet layer | `TestDeclaredOrderSurvivesEveryPermutation`, `TestMTD02RandomizedCompletionOrderNeverReachesTheOutput` | **C23** |
| D07 | JSON byte-identical across runs, modulo time | `TestMTD05AndD07RepeatedRunsAreStable` (100 repetitions), `TestMTD07TheAggregateJSONIsValidAndRoundTrips` | — |
| D08 | Concurrency changes no report content | `TestConcurrencyFourMatchesConcurrencyOne`, `TestConcurrencyOneMatchesTheSequentialReference` | **C25** |

## 6. Report and exit — MT-R01 to MT-R18

| ID | Requirement | Test | Mutation |
|---|---|---|---|
| R01 | Exit 0 — complete, no problems | `TestFourServicesThroughOneRun` (integration) | — |
| R02 | Exit 1 — one target `PROBLEMS_FOUND` | `TestMTR02BlackBoxExitOne`, `TestRunExitCodeMatrix` | **CEX1** |
| R03 | Exit 2 — configuration error, zero targets dialled | `TestMTR03BlackBoxExitTwo`, `TestMTE20AConfigurationErrorDialsNothing` | **CEX3**, **C38** |
| R04 | Exit 3 — forced abort | `TestMTE07AFirstInterruptCancelsAndASecondAborts` | **CEX5** |
| R05 | Exit 4 — any `NOT_STARTED` | `TestMTR05AndR06BlackBoxExitFour`, `TestRunExitCodeMatrix` | — |
| R06 | Exit 4 — any `CANCELLED` | `TestMTR05AndR06BlackBoxExitFour`, `TestRunExitCodeMatrix` | — |
| R07 | Exit 4 — any `EXECUTION_FAILED`, never 3 | `TestRunExitCodeMatrix`, `TestTheChaosMixKeepsEveryTargetIndependent` (integration) | **CEX2** |
| R08 | Exit 4 — any incomplete target report | `TestRunExitCodeMatrix` | — |
| R09 | Exit 4 outranks 1 | `TestExitFourOutranksOneThroughTheRealSurface`, `TestTheWorkedCaseKeepsItsFinding` | **CEX1** |
| R10 | Execution-state presence invariants hold | `TestMTR10ExecutionStatePresenceInvariants` (`internal/domain`), `assertNoFabricatedEvidence`, `TestG1ToG6TheAggregateGoldens` | **C20** |
| R11 | An embedded report is byte-identical to the single-target artifact | `TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun` | — |
| R12 | Every embedded report still carries `schemaVersion: 1` | `TestTheEmbeddedReportSchemaVersionIsStillOne` | — |
| R13 | The run summary is derived and cannot be supplied | `TestMTR13TheRunSummaryIsDerivedAndCannotBeSupplied` (`internal/domain`) | — |
| R14 | The summary never says "healthy" | `TestNeitherRunSummaryBranchDescribesTargetsAsHealthy` | — |
| R15 | A `NOT_STARTED` target has no evidence graph | `TestMTR15NeverStartedTargetsInvokeNothing`, `assertNoFabricatedEvidence` | **C20** |
| R16 | The renderer makes no cross-target claim | `TestNoAggregateSurfaceCombinesTwoTargetsOutcomes`, `TestNoRunSurfaceComparesTwoTargetReports` | **C33** |
| R17 | The three non-completed dispositions render distinguishably | `TestTheTerminalRunOutputDistinguishesDispositions` | — |
| R18 | The renderer does not choose the exit code | `TestTheRendererDoesNotDecideTheExitCode` | **C32** |

**Added in 9.1C.** Six golden fixtures pinning the aggregate's serialized shape —
`test/golden/testdata/g1`…`g6` — covering all-completed, a diagnostic failure, an execution
failure, cancelled-plus-not-started, a four-service run and a shareable mixed run.

## 7. Regression — MT-G01 to MT-G09

| ID | Requirement | Test |
|---|---|---|
| G01–G04 | The four leaf command surfaces are unchanged | `TestTheLeafCommandFlagSurfacesAreUnchanged`, `TestNoLeafCommandGainedAConfigurationFlag` |
| G05 | Finding codes still 60 | `TestMTG05TheFindingCodeCountIsUnchanged` |
| G06 | Failure classes still 42 | `TestFailureClassNamesCoverAllClasses` (`internal/domain`) |
| G07 | `Reveal` still 4, `SecretFor` still 4 | `TestMTG07TheAuthorityCallSiteCountsAreUnchanged` |
| G08 | The module graph is exactly 2 | `TestTheDependencyCountIsExact`, `TestTheModuleGraphIsExactlyWhatWasDecided` (`test/security`) |
| G09 | Root usage gains `run` and changes nothing else | `TestTheRootUsageNamesOnlyImplementedCommands`, `TestTheRunCommandIsRouted` |

**`internal/domain` had no `RunReport` tests at all before 9.1C.** The aggregate, the target
result and the run summary arrived in 9.1B with thorough coverage *through* the scheduler and
the command, and none directly. That is a smaller claim than it looks: it proves the
invariants hold for the values the scheduler happens to produce, and it cannot exercise the
combinations the constructors exist to refuse, because the scheduler never attempts them.
`internal/domain/runreport_test.go` now owns MT-R10 and MT-R13, plus the envelope's own
validation and its copy-on-construction behaviour. This is the gap the reconciliation was for.

**G05 and G07 did not exist before 9.1C.** "Finding codes stay at 60" is an ADR 0073 §12
*decision*, and nothing counted them — the codes are `const` declarations spread across five
diagnosis packages with no central registry, deliberately, so the number lived only in prose.
Both are now counted from the syntax tree.

## 8. What this reconciliation could not prove

Stated because a traceability document that lists only successes is a marketing document.

- **A secret equal to a value the report must carry is indistinguishable.** If an operator's
  password is also their username or their target identifier, those characters appear in the
  report because the *identity* appears in the report. No structural redaction can resolve it.
  `TestASecretEqualToAReportedValueIsIndistinguishable` pins the honest property instead —
  changing the password changes no byte of the output — so the appearance is provably caused
  by the reported value and not by the secret.
- **The post-cancellation race window is guarded structurally, not behaviourally.** The window
  needs a worker parked on the dispatch channel at the instant the run context expires, and
  neither condition can be forced from outside. Mutations C21 and C22 survived every
  behavioural test. `TestTheSchedulerChecksTheRunContextBeforeSpendingAnything` asserts the
  code shape instead. That is a weaker claim than "the race cannot happen", and it is written
  as one.
- **Exit 0 through the real CLI needs a service.** It is owned by the Docker integration suite
  and is not fabricated in-process, because stubbing the composition root would make the test
  about the stub.
- **A YAML tag is named in a refusal, and is excluded from the leakage corpus.** An operator
  told "you used a tag that is not accepted" without being told which one cannot act on it. A
  tag is syntax, not credential material, and no reference shape puts a value there.
- **Target concurrency bounds targets, not sockets.** Unchanged from 9.1B, and 9.1C added no
  global probe semaphore. ADR 0073 §10.1 still declines one.
