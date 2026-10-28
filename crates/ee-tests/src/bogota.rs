//! Bogota code lifecycle regressions (EIP-4758, EIP-8151 and EIP-8298).

use revm::{
    context::TxEnv,
    context_interface::result::{ExecutionResult, ResultAndState},
    database::{CacheDB, EmptyDB},
    primitives::{hardfork::SpecId, Address, Bytes, TxKind, U256},
    state::{AccountInfo, AccountStatus, Bytecode},
    Context, ExecuteEvm, MainBuilder, MainContext,
};

const CALLER: Address = Address::repeat_byte(0xaa);
const TARGET: Address = Address::repeat_byte(0xbb);
const SOURCE: Address = Address::repeat_byte(0xcc);
const SHARED_CODE: &[u8] = &[0x60, 42, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3];

fn adopt(source: Address) -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(source.as_slice());
    code.push(0xa7);
    code
}

fn execute(code: Vec<u8>, source: Option<Bytecode>, spec: SpecId, create: bool) -> ResultAndState {
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(CALLER, AccountInfo::default().with_balance(U256::from(100)));
    if !create {
        db.insert_account_info(
            TARGET,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from(code.clone()))),
        );
    }
    if let Some(source) = source {
        db.insert_account_info(SOURCE, AccountInfo::default().with_code(source));
    }
    let mut evm = Context::mainnet()
        .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(spec))
        .with_db(db)
        .build_mainnet();
    let tx = TxEnv::builder()
        .caller(CALLER)
        .kind(if create {
            TxKind::Create
        } else {
            TxKind::Call(TARGET)
        })
        .data(if create {
            Bytes::from(code)
        } else {
            Bytes::new()
        })
        .gas_limit(5_000_000)
        .gas_price(0)
        .build_fill();
    evm.transact(tx).unwrap()
}

#[test]
fn setcodefrom_updates_account_but_keeps_executing_loaded_code() {
    let source = Bytecode::new_legacy(Bytes::from_static(SHARED_CODE));
    let mut code = adopt(SOURCE);
    code.extend_from_slice(&[0x5f, 0x52, 0x60, 32, 0x5f, 0xf3]);
    let output = execute(code, Some(source.clone()), SpecId::BOGOTA, false);
    assert!(output.result.is_success());
    assert_eq!(
        U256::from_be_slice(output.result.output().unwrap()),
        U256::from(1)
    );
    let target = &output.state[&TARGET];
    assert_eq!(target.info.code_hash, source.hash_slow());
    assert_eq!(target.info.code.as_ref(), Some(&source));
    assert!(target.status.contains(AccountStatus::CodeAdopted));
}

#[test]
fn setcodefrom_is_gated_and_rejects_empty_or_delegated_sources() {
    for source in [
        None,
        Some(Bytecode::default()),
        Some(Bytecode::new_eip7702(TARGET)),
    ] {
        let mut code = adopt(SOURCE);
        code.extend_from_slice(&[0x5f, 0x52, 0x60, 32, 0x5f, 0xf3]);
        let output = execute(code.clone(), source.clone(), SpecId::BOGOTA, false);
        assert!(output.result.is_success());
        assert_eq!(
            U256::from_be_slice(output.result.output().unwrap()),
            U256::ZERO
        );
        assert!(!output.state[&TARGET]
            .status
            .contains(AccountStatus::CodeAdopted));
        let before = execute(code, source, SpecId::AMSTERDAM, false);
        assert!(matches!(before.result, ExecutionResult::Halt { .. }));
    }
}

#[test]
fn setcodefrom_revert_restores_code_and_provenance() {
    let mut code = adopt(SOURCE);
    code.extend_from_slice(&[0x5f, 0x5f, 0xfd]);
    let original_hash = Bytecode::new_legacy(Bytes::from(code.clone())).hash_slow();
    let output = execute(
        code,
        Some(Bytecode::new_legacy(Bytes::from_static(SHARED_CODE))),
        SpecId::BOGOTA,
        false,
    );
    assert!(matches!(output.result, ExecutionResult::Revert { .. }));
    assert_eq!(output.state[&TARGET].info.code_hash, original_hash);
    assert!(!output.state[&TARGET]
        .status
        .contains(AccountStatus::CodeAdopted));
}

#[test]
fn creation_reports_adopted_code_and_ignores_invalid_returned_code() {
    let source = Bytecode::new_legacy(Bytes::from_static(SHARED_CODE));
    let mut initcode = adopt(SOURCE);
    initcode.extend_from_slice(&[0x50, 0x60, 0xef, 0x5f, 0x52, 0x60, 1, 0x60, 31, 0xf3]);
    let output = execute(initcode, Some(source.clone()), SpecId::BOGOTA, true);
    assert!(output.result.is_success());
    assert_eq!(output.result.output().unwrap().as_ref(), SHARED_CODE);
    assert_eq!(
        output.state[&CALLER.create(0)].info.code_hash,
        source.hash_slow()
    );
    assert_eq!(output.result.gas().state_gas_spent_final(), 183_600);
}

#[test]
fn sendall_in_initcode_preserves_nonce_and_storage() {
    let initcode = vec![0x60, 1, 0x5f, 0x55, 0x30, 0xff];
    let output = execute(initcode, None, SpecId::BOGOTA, true);
    assert!(output.result.is_success());
    let created = &output.state[&CALLER.create(0)];
    assert_eq!(created.info.nonce, 1);
    assert_eq!(created.storage[&U256::ZERO].present_value(), U256::from(1));
    assert!(!created.is_selfdestructed());
}

#[test]
fn ecrecover_restriction_runs_after_real_recovery_and_is_fork_gated() {
    let mut input = vec![0u8; 128];
    input[63] = 27;
    input[95] = 1;
    input[127] = 1;
    let pure = revm::precompile::secp256k1::ec_recover_run(&input, 10_000).unwrap();
    assert_eq!(pure.bytes.len(), 32);
    let recovered = Address::from_word(revm::primitives::B256::from_slice(&pure.bytes));
    for (spec, code, permitted) in [
        (SpecId::BOGOTA, Bytecode::default(), true),
        (SpecId::BOGOTA, Bytecode::new_eip7702(TARGET), true),
        (
            SpecId::BOGOTA,
            Bytecode::new_legacy(Bytes::from_static(&[0x00])),
            false,
        ),
        (
            SpecId::AMSTERDAM,
            Bytecode::new_legacy(Bytes::from_static(&[0x00])),
            true,
        ),
    ] {
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(CALLER, AccountInfo::default().with_balance(U256::from(100)));
        db.insert_account_info(recovered, AccountInfo::default().with_code(code));
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(spec))
            .with_db(db)
            .build_mainnet();
        let tx = TxEnv::builder()
            .caller(CALLER)
            .kind(TxKind::Call(Address::with_last_byte(1)))
            .data(Bytes::from(input.clone()))
            .gas_limit(100_000)
            .gas_price(0)
            .build_fill();
        let output = evm.transact(tx).unwrap();
        assert!(output.result.is_success());
        assert_eq!(
            output.result.output().unwrap().len(),
            if permitted { 32 } else { 0 }
        );
        assert_eq!(
            output.state.contains_key(&recovered),
            spec == SpecId::BOGOTA
        );
        assert!(!output.state.contains_key(&TARGET));
    }
}

#[test]
fn setcodefrom_charges_before_mutation_and_rejects_new_sources() {
    use revm::context_interface::{ContextTr, Host, JournalTr};
    for (warm, gas, succeeds, expected) in [
        (false, 12_199, false, 0),
        (false, 12_200, true, 12_200),
        (true, 9_299, false, 0),
        (true, 9_300, true, 9_300),
    ] {
        let mut db = CacheDB::<EmptyDB>::default();
        let original = Bytecode::new_legacy(Bytes::from_static(&[0x00]));
        db.insert_account_info(TARGET, AccountInfo::default().with_code(original.clone()));
        db.insert_account_info(
            SOURCE,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(SHARED_CODE))),
        );
        let mut ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db);
        ctx.journal_mut().load_account(TARGET).unwrap();
        if warm {
            ctx.journal_mut().load_account(SOURCE).unwrap();
        }
        let result = ctx.set_code_from(TARGET, SOURCE, gas);
        assert_eq!(result.is_ok(), succeeds);
        if succeeds {
            assert_eq!(result.unwrap(), (true, expected));
            assert_eq!(ctx.set_code_from(TARGET, SOURCE, 300).unwrap(), (true, 300));
        } else {
            assert_eq!(
                ctx.journaled_state.state[&TARGET].info.code_hash,
                original.hash_slow()
            );
        }
        ctx.journaled_state
            .state
            .get_mut(&SOURCE)
            .unwrap()
            .mark_created_locally();
        assert_eq!(
            ctx.set_code_from(TARGET, SOURCE, 200).unwrap(),
            (false, 200)
        );
    }
}

#[test]
fn setcodefrom_system_calls_keep_code_and_storage_changes_at_one_bal_index() {
    use revm::{database::State, handler::SystemCallCommitEvm, state::bal::BlockAccessIndex};

    let second_source = Address::repeat_byte(0xce);
    for (index, calls) in [(0, 2), (1, 4)] {
        for readopt in [false, true] {
            let marker = if readopt { 43 } else { 42 };
            let mut marker_code = vec![0x60, marker, 0x60, 1, 0x55];
            let mut source_code = marker_code.clone();
            if readopt {
                source_code.extend(adopt(second_source));
                source_code.push(0x50);
            }
            source_code.push(0x00);
            marker_code.push(0x00);
            let final_code = Bytecode::new_legacy(Bytes::from(if readopt {
                marker_code.clone()
            } else {
                source_code.clone()
            }));

            let mut shell = adopt(SOURCE);
            shell.extend_from_slice(&[0x5f, 0x55, 0x00]);
            let mut db = CacheDB::<EmptyDB>::default();
            db.insert_account_info(
                TARGET,
                AccountInfo::default().with_code(Bytecode::new_legacy(shell.into())),
            );
            db.insert_account_info(
                SOURCE,
                AccountInfo::default().with_code(Bytecode::new_legacy(source_code.into())),
            );
            db.insert_account_info(
                second_source,
                AccountInfo::default().with_code(Bytecode::new_legacy(marker_code.into())),
            );

            let mut driver_code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x73];
            driver_code.extend_from_slice(TARGET.as_slice());
            driver_code.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40, 0xf1, 0x50, 0x00]);
            let drivers = (0..calls)
                .map(|i| Address::repeat_byte(0xd0 + i))
                .collect::<Vec<_>>();
            for driver in &drivers {
                db.insert_account_info(
                    *driver,
                    AccountInfo::default()
                        .with_balance(U256::from(1))
                        .with_code(Bytecode::new_legacy(driver_code.clone().into())),
                );
            }
            let mut state = State::builder()
                .with_database(db)
                .with_bal_builder()
                .build();
            state.set_bal_index(BlockAccessIndex::new(index));
            let mut evm = Context::mainnet()
                .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
                .with_db(state)
                .build_mainnet();
            for driver in drivers {
                assert!(evm
                    .system_call_commit(driver, Bytes::new())
                    .unwrap()
                    .is_success());
            }
            let bal = evm
                .ctx
                .journaled_state
                .database
                .take_built_alloy_bal()
                .unwrap();
            let shell = bal
                .iter()
                .find(|account| account.address == TARGET)
                .unwrap();
            assert_eq!(
                shell.code_changes.len(),
                1,
                "index={index}, readopt={readopt}"
            );
            assert_eq!(
                shell.code_changes[0].block_access_index,
                BlockAccessIndex::new(index)
            );
            assert_eq!(
                shell.code_changes[0].adopted_code_hash(),
                Some(final_code.hash_slow())
            );
            assert_eq!(shell.balance_changes[0].post_balance, U256::from(calls));
            assert_eq!(shell.storage_changes.len(), 2);
            assert_eq!(shell.storage_changes[0].slot, U256::ZERO);
            assert_eq!(shell.storage_changes[0].changes[0].new_value, U256::from(1));
            assert_eq!(shell.storage_changes[1].slot, U256::from(1));
            assert_eq!(
                shell.storage_changes[1].changes[0].new_value,
                U256::from(marker)
            );
        }
    }
}
