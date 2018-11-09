(module
 (type $FUNCSIG$vii (func (param i32 i32)))
 (type $FUNCSIG$viiii (func (param i32 i32 i32 i32)))
 (type $FUNCSIG$viiiiii (func (param i32 i32 i32 i32 i32 i32)))
 (type $FUNCSIG$viiiiiii (func (param i32 i32 i32 i32 i32 i32 i32)))
 (type $FUNCSIG$viii (func (param i32 i32 i32)))
 (type $FUNCSIG$viiiii (func (param i32 i32 i32 i32 i32)))
 (type $FUNCSIG$v (func))
 (type $FUNCSIG$j (func (result i64)))
 (type $FUNCSIG$vjj (func (param i64 i64)))
 (type $FUNCSIG$i (func (result i32)))
 (type $FUNCSIG$iii (func (param i32 i32) (result i32)))
 (type $FUNCSIG$iiii (func (param i32 i32 i32) (result i32)))
 (type $FUNCSIG$ijjjj (func (param i64 i64 i64 i64) (result i32)))
 (type $FUNCSIG$vijii (func (param i32 i64 i32 i32)))
 (type $FUNCSIG$ijjjjii (func (param i64 i64 i64 i64 i32 i32) (result i32)))
 (type $FUNCSIG$ijjj (func (param i64 i64 i64) (result i32)))
 (type $FUNCSIG$vi (func (param i32)))
 (type $FUNCSIG$vj (func (param i64)))
 (import "env" "abort" (func $abort))
 (import "env" "action_data_size" (func $action_data_size (result i32)))
 (import "env" "current_receiver" (func $current_receiver (result i64)))
 (import "env" "current_time" (func $current_time (result i64)))
 (import "env" "db_end_i64" (func $db_end_i64 (param i64 i64 i64) (result i32)))
 (import "env" "db_find_i64" (func $db_find_i64 (param i64 i64 i64 i64) (result i32)))
 (import "env" "db_get_i64" (func $db_get_i64 (param i32 i32 i32) (result i32)))
 (import "env" "db_lowerbound_i64" (func $db_lowerbound_i64 (param i64 i64 i64 i64) (result i32)))
 (import "env" "db_previous_i64" (func $db_previous_i64 (param i32 i32) (result i32)))
 (import "env" "db_store_i64" (func $db_store_i64 (param i64 i64 i64 i64 i32 i32) (result i32)))
 (import "env" "db_update_i64" (func $db_update_i64 (param i32 i64 i32 i32)))
 (import "env" "eosio_assert" (func $eosio_assert (param i32 i32)))
 (import "env" "memcpy" (func $memcpy (param i32 i32 i32) (result i32)))
 (import "env" "memmove" (func $memmove (param i32 i32 i32) (result i32)))
 (import "env" "prints" (func $prints (param i32)))
 (import "env" "read_action_data" (func $read_action_data (param i32 i32) (result i32)))
 (import "env" "require_auth" (func $require_auth (param i64)))
 (import "env" "require_auth2" (func $require_auth2 (param i64 i64)))
 (import "env" "send_inline" (func $send_inline (param i32 i32)))
 (table 14 14 anyfunc)
 (elem (i32.const 0) $__wasm_nullptr $_ZN21UnificationFoundation16unification_uapp10editschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_ $_ZN21UnificationFoundation16unification_uapp11setpriceschERKyRKh $_ZN21UnificationFoundation16unification_uapp9updatereqERKyS2_RKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_ $_ZN21UnificationFoundation16unification_uapp9setschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE $_ZN21UnificationFoundation16unification_uapp8initpermERKy $_ZN21UnificationFoundation16unification_uapp9addschemaERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEERKhSB_SB_SB_ $_ZN21UnificationFoundation16unification_uapp10modifypermERKyS2_RKh $_ZN21UnificationFoundation16unification_uapp11setpriceadhERKyRKh $_ZN21UnificationFoundation16unification_uapp7setversERKyRKh $_ZN21UnificationFoundation16unification_uapp10updatepermERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_ $_ZN21UnificationFoundation16unification_uapp9setrsakeyENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE $_ZN21UnificationFoundation16unification_uapp11setscheduleERKyRKh $_ZN21UnificationFoundation16unification_uapp7initreqERKyS2_RKhRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEES4_)
 (memory $0 1)
 (data (i32.const 4) "\90e\00\00")
 (data (i32.const 16) "onerror\00")
 (data (i32.const 32) "eosio\00")
 (data (i32.const 48) "onerror action\'s are only valid from the \"eosio\" system account\00")
 (data (i32.const 112) "get\00")
 (data (i32.const 128) "read\00")
 (data (i32.const 144) "modrsakey\00")
 (data (i32.const 160) "cannot create objects in table of another contract\00")
 (data (i32.const 224) "object passed to iterator_to is not in multi_index\00")
 (data (i32.const 288) "cannot pass end iterator to modify\00")
 (data (i32.const 336) "object passed to modify is not in multi_index\00")
 (data (i32.const 384) "cannot modify objects in table of another contract\00")
 (data (i32.const 448) "updater cannot change primary key when modifying an object\00")
 (data (i32.const 512) "write\00")
 (data (i32.const 528) "error reading iterator\00")
 (data (i32.const 560) "next primary key in table is at autoincrement limit\00")
 (data (i32.const 624) "cannot decrement end iterator when the table is empty\00")
 (data (i32.const 688) "cannot decrement iterator at beginning of table\00")
 (data (i32.const 736) "modreq\00")
 (data (i32.const 752) "Data request not found\00")
 (data (i32.const 784) "Calling account and provider_name mismatch\00")
 (data (i32.const 832) "initperm\00")
 (data (i32.const 848) "modschema\00")
 (data (i32.const 864) "Schema not found\00")
 (data (i32.const 896) "schedule must 1, 2 or 3 for daily, weekly, monthly\00")
 (data (i32.const 960) "schema_vers must 0 or 1 for dev, prod\00")
 (data (i32.const 1008) "addschema()\00")
 (data (i32.const 1024) "Permission relationship not found\00")
 (data (i32.const 1072) "0000000000000000000000000000000000000000000000\00")
 (data (i32.const 9520) "malloc_from_freed was designed to only be called after _heap was completely allocated\00")
 (export "memory" (memory $0))
 (export "_ZeqRK11checksum256S1_" (func $_ZeqRK11checksum256S1_))
 (export "_ZeqRK11checksum160S1_" (func $_ZeqRK11checksum160S1_))
 (export "_ZneRK11checksum160S1_" (func $_ZneRK11checksum160S1_))
 (export "now" (func $now))
 (export "_ZN5eosio12require_authERKNS_16permission_levelE" (func $_ZN5eosio12require_authERKNS_16permission_levelE))
 (export "apply" (func $apply))
 (export "_ZN21UnificationFoundation16unification_uapp8initpermERKy" (func $_ZN21UnificationFoundation16unification_uapp8initpermERKy))
 (export "_ZN21UnificationFoundation16unification_uapp10updatepermERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_" (func $_ZN21UnificationFoundation16unification_uapp10updatepermERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_))
 (export "_ZN21UnificationFoundation16unification_uapp10modifypermERKyS2_RKh" (func $_ZN21UnificationFoundation16unification_uapp10modifypermERKyS2_RKh))
 (export "_ZN21UnificationFoundation16unification_uapp9addschemaERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEERKhSB_SB_SB_" (func $_ZN21UnificationFoundation16unification_uapp9addschemaERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEERKhSB_SB_SB_))
 (export "_ZN21UnificationFoundation16unification_uapp10editschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_" (func $_ZN21UnificationFoundation16unification_uapp10editschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_))
 (export "_ZN21UnificationFoundation16unification_uapp7setversERKyRKh" (func $_ZN21UnificationFoundation16unification_uapp7setversERKyRKh))
 (export "_ZN21UnificationFoundation16unification_uapp11setscheduleERKyRKh" (func $_ZN21UnificationFoundation16unification_uapp11setscheduleERKyRKh))
 (export "_ZN21UnificationFoundation16unification_uapp11setpriceschERKyRKh" (func $_ZN21UnificationFoundation16unification_uapp11setpriceschERKyRKh))
 (export "_ZN21UnificationFoundation16unification_uapp11setpriceadhERKyRKh" (func $_ZN21UnificationFoundation16unification_uapp11setpriceadhERKyRKh))
 (export "_ZN21UnificationFoundation16unification_uapp9setschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE" (func $_ZN21UnificationFoundation16unification_uapp9setschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE))
 (export "_ZN21UnificationFoundation16unification_uapp7initreqERKyS2_RKhRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEES4_" (func $_ZN21UnificationFoundation16unification_uapp7initreqERKyS2_RKhRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEES4_))
 (export "_ZN21UnificationFoundation16unification_uapp9updatereqERKyS2_RKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_" (func $_ZN21UnificationFoundation16unification_uapp9updatereqERKyS2_RKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_))
 (export "_ZN21UnificationFoundation16unification_uapp9setrsakeyENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE" (func $_ZN21UnificationFoundation16unification_uapp9setrsakeyENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE))
 (export "_ZN21UnificationFoundation16unification_uappC2Ey" (func $_ZN21UnificationFoundation16unification_uappC2Ey))
 (export "malloc" (func $malloc))
 (export "free" (func $free))
 (export "strlen" (func $strlen))
 (export "memcmp" (func $memcmp))
 (func $_ZeqRK11checksum256S1_ (param $0 i32) (param $1 i32) (result i32)
  (i32.eqz
   (call $memcmp
    (get_local $0)
    (get_local $1)
    (i32.const 32)
   )
  )
 )
 (func $_ZeqRK11checksum160S1_ (param $0 i32) (param $1 i32) (result i32)
  (i32.eqz
   (call $memcmp
    (get_local $0)
    (get_local $1)
    (i32.const 32)
   )
  )
 )
 (func $_ZneRK11checksum160S1_ (param $0 i32) (param $1 i32) (result i32)
  (i32.ne
   (call $memcmp
    (get_local $0)
    (get_local $1)
    (i32.const 32)
   )
   (i32.const 0)
  )
 )
 (func $now (result i32)
  (i32.wrap/i64
   (i64.div_u
    (call $current_time)
    (i64.const 1000000)
   )
  )
 )
 (func $_ZN5eosio12require_authERKNS_16permission_levelE (param $0 i32)
  (call $require_auth2
   (i64.load
    (get_local $0)
   )
   (i64.load offset=8
    (get_local $0)
   )
  )
 )
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 224)
    )
   )
  )
  (set_local $6
   (i64.const 0)
  )
  (set_local $5
   (i64.const 59)
  )
  (set_local $4
   (i32.const 16)
  )
  (set_local $7
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $6)
          (i64.const 6)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $3
             (i32.load8_s
              (get_local $4)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $3
         (i32.add
          (get_local $3)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $8
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $6)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $3
       (select
        (i32.add
         (get_local $3)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $3)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $8
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $3)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $8
     (i64.shl
      (i64.and
       (get_local $8)
       (i64.const 31)
      )
      (i64.and
       (get_local $5)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
   (set_local $6
    (i64.add
     (get_local $6)
     (i64.const 1)
    )
   )
   (set_local $7
    (i64.or
     (get_local $8)
     (get_local $7)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $5
      (i64.add
       (get_local $5)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i64.ne
     (get_local $7)
     (get_local $2)
    )
   )
   (set_local $6
    (i64.const 0)
   )
   (set_local $5
    (i64.const 59)
   )
   (set_local $4
    (i32.const 32)
   )
   (set_local $7
    (i64.const 0)
   )
   (loop $label$7
    (block $label$8
     (block $label$9
      (block $label$10
       (block $label$11
        (block $label$12
         (br_if $label$12
          (i64.gt_u
           (get_local $6)
           (i64.const 4)
          )
         )
         (br_if $label$11
          (i32.gt_u
           (i32.and
            (i32.add
             (tee_local $3
              (i32.load8_s
               (get_local $4)
              )
             )
             (i32.const -97)
            )
            (i32.const 255)
           )
           (i32.const 25)
          )
         )
         (set_local $3
          (i32.add
           (get_local $3)
           (i32.const 165)
          )
         )
         (br $label$10)
        )
        (set_local $8
         (i64.const 0)
        )
        (br_if $label$9
         (i64.le_u
          (get_local $6)
          (i64.const 11)
         )
        )
        (br $label$8)
       )
       (set_local $3
        (select
         (i32.add
          (get_local $3)
          (i32.const 208)
         )
         (i32.const 0)
         (i32.lt_u
          (i32.and
           (i32.add
            (get_local $3)
            (i32.const -49)
           )
           (i32.const 255)
          )
          (i32.const 5)
         )
        )
       )
      )
      (set_local $8
       (i64.shr_s
        (i64.shl
         (i64.extend_u/i32
          (get_local $3)
         )
         (i64.const 56)
        )
        (i64.const 56)
       )
      )
     )
     (set_local $8
      (i64.shl
       (i64.and
        (get_local $8)
        (i64.const 31)
       )
       (i64.and
        (get_local $5)
        (i64.const 4294967295)
       )
      )
     )
    )
    (set_local $4
     (i32.add
      (get_local $4)
      (i32.const 1)
     )
    )
    (set_local $6
     (i64.add
      (get_local $6)
      (i64.const 1)
     )
    )
    (set_local $7
     (i64.or
      (get_local $8)
      (get_local $7)
     )
    )
    (br_if $label$7
     (i64.ne
      (tee_local $5
       (i64.add
        (get_local $5)
        (i64.const -5)
       )
      )
      (i64.const -6)
     )
    )
   )
   (call $eosio_assert
    (i64.eq
     (get_local $7)
     (get_local $1)
    )
    (i32.const 48)
   )
  )
  (block $label$13
   (block $label$14
    (br_if $label$14
     (i64.eq
      (get_local $1)
      (get_local $0)
     )
    )
    (set_local $6
     (i64.const 0)
    )
    (set_local $5
     (i64.const 59)
    )
    (set_local $4
     (i32.const 16)
    )
    (set_local $7
     (i64.const 0)
    )
    (loop $label$15
     (block $label$16
      (block $label$17
       (block $label$18
        (block $label$19
         (block $label$20
          (br_if $label$20
           (i64.gt_u
            (get_local $6)
            (i64.const 6)
           )
          )
          (br_if $label$19
           (i32.gt_u
            (i32.and
             (i32.add
              (tee_local $3
               (i32.load8_s
                (get_local $4)
               )
              )
              (i32.const -97)
             )
             (i32.const 255)
            )
            (i32.const 25)
           )
          )
          (set_local $3
           (i32.add
            (get_local $3)
            (i32.const 165)
           )
          )
          (br $label$18)
         )
         (set_local $8
          (i64.const 0)
         )
         (br_if $label$17
          (i64.le_u
           (get_local $6)
           (i64.const 11)
          )
         )
         (br $label$16)
        )
        (set_local $3
         (select
          (i32.add
           (get_local $3)
           (i32.const 208)
          )
          (i32.const 0)
          (i32.lt_u
           (i32.and
            (i32.add
             (get_local $3)
             (i32.const -49)
            )
            (i32.const 255)
           )
           (i32.const 5)
          )
         )
        )
       )
       (set_local $8
        (i64.shr_s
         (i64.shl
          (i64.extend_u/i32
           (get_local $3)
          )
          (i64.const 56)
         )
         (i64.const 56)
        )
       )
      )
      (set_local $8
       (i64.shl
        (i64.and
         (get_local $8)
         (i64.const 31)
        )
        (i64.and
         (get_local $5)
         (i64.const 4294967295)
        )
       )
      )
     )
     (set_local $4
      (i32.add
       (get_local $4)
       (i32.const 1)
      )
     )
     (set_local $6
      (i64.add
       (get_local $6)
       (i64.const 1)
      )
     )
     (set_local $7
      (i64.or
       (get_local $8)
       (get_local $7)
      )
     )
     (br_if $label$15
      (i64.ne
       (tee_local $5
        (i64.add
         (get_local $5)
         (i64.const -5)
        )
       )
       (i64.const -6)
      )
     )
    )
    (br_if $label$13
     (i64.ne
      (get_local $7)
      (get_local $2)
     )
    )
   )
   (i64.store offset=216
    (get_local $9)
    (get_local $0)
   )
   (block $label$21
    (block $label$22
     (block $label$23
      (block $label$24
       (block $label$25
        (block $label$26
         (block $label$27
          (block $label$28
           (block $label$29
            (block $label$30
             (block $label$31
              (block $label$32
               (br_if $label$32
                (i64.le_s
                 (get_local $2)
                 (i64.const -4416987389893804033)
                )
               )
               (br_if $label$31
                (i64.le_s
                 (get_local $2)
                 (i64.const 3626387489510391807)
                )
               )
               (br_if $label$29
                (i64.gt_s
                 (get_local $2)
                 (i64.const 8421056937247899647)
                )
               )
               (br_if $label$28
                (i64.eq
                 (get_local $2)
                 (i64.const 3626387489510391808)
                )
               )
               (br_if $label$13
                (i64.ne
                 (get_local $2)
                 (i64.const 5935071552353697792)
                )
               )
               (i32.store offset=180
                (get_local $9)
                (i32.const 0)
               )
               (i32.store offset=176
                (get_local $9)
                (i32.const 1)
               )
               (i64.store offset=40 align=4
                (get_local $9)
                (i64.load offset=176
                 (get_local $9)
                )
               )
               (drop
                (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERKhSF_SF_SF_EEEbPT_MT0_FvDpT1_E
                 (i32.add
                  (get_local $9)
                  (i32.const 216)
                 )
                 (i32.add
                  (get_local $9)
                  (i32.const 40)
                 )
                )
               )
               (br $label$13)
              )
              (br_if $label$30
               (i64.gt_s
                (get_local $2)
                (i64.const -4417050358225829889)
               )
              )
              (br_if $label$27
               (i64.eq
                (get_local $2)
                (i64.const -7704843147708432384)
               )
              )
              (br_if $label$26
               (i64.eq
                (get_local $2)
                (i64.const -4417085959222175232)
               )
              )
              (br_if $label$13
               (i64.ne
                (get_local $2)
                (i64.const -4417085959212754432)
               )
              )
              (i32.store offset=156
               (get_local $9)
               (i32.const 0)
              )
              (i32.store offset=152
               (get_local $9)
               (i32.const 2)
              )
              (i64.store offset=64 align=4
               (get_local $9)
               (i64.load offset=152
                (get_local $9)
               )
              )
              (drop
               (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKhEEEbPT_MT0_FvDpT1_E
                (i32.add
                 (get_local $9)
                 (i32.const 216)
                )
                (i32.add
                 (get_local $9)
                 (i32.const 64)
                )
               )
              )
              (br $label$13)
             )
             (br_if $label$25
              (i64.eq
               (get_local $2)
               (i64.const -4416987389893804032)
              )
             )
             (br_if $label$24
              (i64.eq
               (get_local $2)
               (i64.const -3075276115275907072)
              )
             )
             (br_if $label$13
              (i64.ne
               (get_local $2)
               (i64.const -3075276114202984448)
              )
             )
             (i32.store offset=124
              (get_local $9)
              (i32.const 0)
             )
             (i32.store offset=120
              (get_local $9)
              (i32.const 3)
             )
             (i64.store offset=96 align=4
              (get_local $9)
              (i64.load offset=120
               (get_local $9)
              )
             )
             (drop
              (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_EEEbPT_MT0_FvDpT1_E
               (i32.add
                (get_local $9)
                (i32.const 216)
               )
               (i32.add
                (get_local $9)
                (i32.const 96)
               )
              )
             )
             (br $label$13)
            )
            (br_if $label$23
             (i64.eq
              (get_local $2)
              (i64.const -4417050358225829888)
             )
            )
            (br_if $label$22
             (i64.eq
              (get_local $2)
              (i64.const -4417041445113539584)
             )
            )
            (br_if $label$13
             (i64.ne
              (get_local $2)
              (i64.const -4417041444973314048)
             )
            )
            (i32.store offset=140
             (get_local $9)
             (i32.const 0)
            )
            (i32.store offset=136
             (get_local $9)
             (i32.const 4)
            )
            (i64.store offset=80 align=4
             (get_local $9)
             (i64.load offset=136
              (get_local $9)
             )
            )
            (drop
             (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEEEEEbPT_MT0_FvDpT1_E
              (i32.add
               (get_local $9)
               (i32.const 216)
              )
              (i32.add
               (get_local $9)
               (i32.const 80)
              )
             )
            )
            (br $label$13)
           )
           (br_if $label$21
            (i64.eq
             (get_local $2)
             (i64.const 8421058035920666624)
            )
           )
           (br_if $label$13
            (i64.ne
             (get_local $2)
             (i64.const 8421056937247899648)
            )
           )
           (i32.store offset=212
            (get_local $9)
            (i32.const 0)
           )
           (i32.store offset=208
            (get_local $9)
            (i32.const 5)
           )
           (i64.store offset=8 align=4
            (get_local $9)
            (i64.load offset=208
             (get_local $9)
            )
           )
           (drop
            (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyEEEbPT_MT0_FvDpT1_E
             (i32.add
              (get_local $9)
              (i32.const 216)
             )
             (i32.add
              (get_local $9)
              (i32.const 8)
             )
            )
           )
           (br $label$13)
          )
          (i32.store offset=188
           (get_local $9)
           (i32.const 0)
          )
          (i32.store offset=184
           (get_local $9)
           (i32.const 6)
          )
          (i64.store offset=32 align=4
           (get_local $9)
           (i64.load offset=184
            (get_local $9)
           )
          )
          (drop
           (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_EEEbPT_MT0_FvDpT1_E
            (i32.add
             (get_local $9)
             (i32.const 216)
            )
            (i32.add
             (get_local $9)
             (i32.const 32)
            )
           )
          )
          (br $label$13)
         )
         (i32.store offset=196
          (get_local $9)
          (i32.const 0)
         )
         (i32.store offset=192
          (get_local $9)
          (i32.const 7)
         )
         (i64.store offset=24 align=4
          (get_local $9)
          (i64.load offset=192
           (get_local $9)
          )
         )
         (drop
          (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKhEEEbPT_MT0_FvDpT1_E
           (i32.add
            (get_local $9)
            (i32.const 216)
           )
           (i32.add
            (get_local $9)
            (i32.const 24)
           )
          )
         )
         (br $label$13)
        )
        (i32.store offset=148
         (get_local $9)
         (i32.const 0)
        )
        (i32.store offset=144
         (get_local $9)
         (i32.const 8)
        )
        (i64.store offset=72 align=4
         (get_local $9)
         (i64.load offset=144
          (get_local $9)
         )
        )
        (drop
         (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKhEEEbPT_MT0_FvDpT1_E
          (i32.add
           (get_local $9)
           (i32.const 216)
          )
          (i32.add
           (get_local $9)
           (i32.const 72)
          )
         )
        )
        (br $label$13)
       )
       (i32.store offset=172
        (get_local $9)
        (i32.const 0)
       )
       (i32.store offset=168
        (get_local $9)
        (i32.const 9)
       )
       (i64.store offset=48 align=4
        (get_local $9)
        (i64.load offset=168
         (get_local $9)
        )
       )
       (drop
        (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKhEEEbPT_MT0_FvDpT1_E
         (i32.add
          (get_local $9)
          (i32.const 216)
         )
         (i32.add
          (get_local $9)
          (i32.const 48)
         )
        )
       )
       (br $label$13)
      )
      (i32.store offset=204
       (get_local $9)
       (i32.const 0)
      )
      (i32.store offset=200
       (get_local $9)
       (i32.const 10)
      )
      (i64.store offset=16 align=4
       (get_local $9)
       (i64.load offset=200
        (get_local $9)
       )
      )
      (drop
       (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_EEEbPT_MT0_FvDpT1_E
        (i32.add
         (get_local $9)
         (i32.const 216)
        )
        (i32.add
         (get_local $9)
         (i32.const 16)
        )
       )
      )
      (br $label$13)
     )
     (i32.store offset=116
      (get_local $9)
      (i32.const 0)
     )
     (i32.store offset=112
      (get_local $9)
      (i32.const 11)
     )
     (i64.store offset=104 align=4
      (get_local $9)
      (i64.load offset=112
       (get_local $9)
      )
     )
     (drop
      (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEEEEbPT_MT0_FvDpT1_E
       (i32.add
        (get_local $9)
        (i32.const 216)
       )
       (i32.add
        (get_local $9)
        (i32.const 104)
       )
      )
     )
     (br $label$13)
    )
    (i32.store offset=164
     (get_local $9)
     (i32.const 0)
    )
    (i32.store offset=160
     (get_local $9)
     (i32.const 12)
    )
    (i64.store offset=56 align=4
     (get_local $9)
     (i64.load offset=160
      (get_local $9)
     )
    )
    (drop
     (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKhEEEbPT_MT0_FvDpT1_E
      (i32.add
       (get_local $9)
       (i32.const 216)
      )
      (i32.add
       (get_local $9)
       (i32.const 56)
      )
     )
    )
    (br $label$13)
   )
   (i32.store offset=132
    (get_local $9)
    (i32.const 0)
   )
   (i32.store offset=128
    (get_local $9)
    (i32.const 13)
   )
   (i64.store offset=88 align=4
    (get_local $9)
    (i64.load offset=128
     (get_local $9)
    )
   )
   (drop
    (call $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKhRKNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEES6_EEEbPT_MT0_FvDpT1_E
     (i32.add
      (get_local $9)
      (i32.const 216)
     )
     (i32.add
      (get_local $9)
      (i32.const 88)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $9)
    (i32.const 224)
   )
  )
 )
 (func $_ZN21UnificationFoundation16unification_uapp8initpermERKy (type $FUNCSIG$vii) (param $0 i32) (param $1 i32)
  (local $2 i64)
  (local $3 i32)
  (local $4 i64)
  (local $5 i64)
  (local $6 i64)
  (local $7 i64)
  (local $8 i32)
  (local $9 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 96)
    )
   )
  )
  (set_local $2
   (i64.load
    (get_local $1)
   )
  )
  (set_local $5
   (i64.const 0)
  )
  (set_local $4
   (i64.const 59)
  )
  (set_local $3
   (i32.const 736)
  )
  (set_local $6
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $5)
          (i64.const 5)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $8
             (i32.load8_s
              (get_local $3)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $8
         (i32.add
          (get_local $8)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $7
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $5)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $8
       (select
        (i32.add
         (get_local $8)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $8)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $7
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $8)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $7
     (i64.shl
      (i64.and
       (get_local $7)
       (i64.const 31)
      )
      (i64.and
       (get_local $4)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (set_local $5
    (i64.add
     (get_local $5)
     (i64.const 1)
    )
   )
   (set_local $6
    (i64.or
     (get_local $7)
     (get_local $6)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $4
      (i64.add
       (get_local $4)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $2)
   (get_local $6)
  )
  (i64.store offset=32
   (get_local $9)
   (i64.const -1)
  )
  (i32.store offset=40
   (get_local $9)
   (i32.const 0)
  )
  (i64.store offset=16
   (get_local $9)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=24
   (get_local $9)
   (tee_local $5
    (i64.load
     (get_local $1)
    )
   )
  )
  (i32.store
   (tee_local $8
    (i32.add
     (get_local $9)
     (i32.const 44)
    )
   )
   (i32.const 0)
  )
  (i32.store
   (tee_local $0
    (i32.add
     (get_local $9)
     (i32.const 48)
    )
   )
   (i32.const 0)
  )
  (block $label$6
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.lt_s
       (tee_local $3
        (call $db_find_i64
         (get_local $7)
         (get_local $5)
         (i64.const -3020373100446351360)
         (get_local $5)
        )
       )
       (i32.const 0)
      )
     )
     (call $eosio_assert
      (i32.eq
       (i32.load offset=32
        (call $_ZNK5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE31load_object_by_primary_iteratorEl
         (i32.add
          (get_local $9)
          (i32.const 16)
         )
         (get_local $3)
        )
       )
       (i32.add
        (get_local $9)
        (i32.const 16)
       )
      )
      (i32.const 224)
     )
     (br_if $label$7
      (tee_local $1
       (i32.load offset=40
        (get_local $9)
       )
      )
     )
     (br $label$6)
    )
    (set_local $5
     (i64.load
      (get_local $1)
     )
    )
    (i32.store offset=8
     (get_local $9)
     (get_local $1)
    )
    (i64.store offset=88
     (get_local $9)
     (get_local $5)
    )
    (call $eosio_assert
     (i64.eq
      (get_local $7)
      (call $current_receiver)
     )
     (i32.const 160)
    )
    (i32.store offset=68
     (get_local $9)
     (i32.add
      (get_local $9)
      (i32.const 8)
     )
    )
    (i32.store offset=64
     (get_local $9)
     (i32.add
      (get_local $9)
      (i32.const 16)
     )
    )
    (i32.store offset=72
     (get_local $9)
     (i32.add
      (get_local $9)
      (i32.const 88)
     )
    )
    (i64.store offset=8 align=4
     (tee_local $3
      (call $_Znwj
       (i32.const 48)
      )
     )
     (i64.const 0)
    )
    (i64.store offset=16 align=4
     (get_local $3)
     (i64.const 0)
    )
    (i64.store offset=24 align=4
     (get_local $3)
     (i64.const 0)
    )
    (i32.store offset=32
     (get_local $3)
     (i32.add
      (get_local $9)
      (i32.const 16)
     )
    )
    (call $_ZZN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE7emplaceIZNS2_8initpermERKyE3$_0EENS4_14const_iteratorEyOT_ENKUlRSA_E_clINS4_4itemEEEDaSC_
     (i32.add
      (get_local $9)
      (i32.const 64)
     )
     (get_local $3)
    )
    (i32.store offset=80
     (get_local $9)
     (get_local $3)
    )
    (i64.store offset=64
     (get_local $9)
     (tee_local $5
      (i64.load
       (get_local $3)
      )
     )
    )
    (i32.store offset=60
     (get_local $9)
     (tee_local $1
      (i32.load offset=36
       (get_local $3)
      )
     )
    )
    (block $label$9
     (block $label$10
      (br_if $label$10
       (i32.ge_u
        (tee_local $8
         (i32.load
          (get_local $8)
         )
        )
        (i32.load
         (get_local $0)
        )
       )
      )
      (i64.store offset=8
       (get_local $8)
       (get_local $5)
      )
      (i32.store offset=16
       (get_local $8)
       (get_local $1)
      )
      (i32.store offset=80
       (get_local $9)
       (i32.const 0)
      )
      (i32.store
       (get_local $8)
       (get_local $3)
      )
      (i32.store
       (i32.add
        (get_local $9)
        (i32.const 44)
       )
       (i32.add
        (get_local $8)
        (i32.const 24)
       )
      )
      (br $label$9)
     )
     (call $_ZNSt3__16vectorIN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
      (i32.add
       (get_local $9)
       (i32.const 40)
      )
      (i32.add
       (get_local $9)
       (i32.const 80)
      )
      (i32.add
       (get_local $9)
       (i32.const 64)
      )
      (i32.add
       (get_local $9)
       (i32.const 60)
      )
     )
    )
    (set_local $3
     (i32.load offset=80
      (get_local $9)
     )
    )
    (i32.store offset=80
     (get_local $9)
     (i32.const 0)
    )
    (block $label$11
     (br_if $label$11
      (i32.eqz
       (get_local $3)
      )
     )
     (block $label$12
      (br_if $label$12
       (i32.eqz
        (i32.and
         (i32.load8_u offset=20
          (get_local $3)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $3)
         (i32.const 28)
        )
       )
      )
     )
     (block $label$13
      (br_if $label$13
       (i32.eqz
        (i32.and
         (i32.load8_u offset=8
          (get_local $3)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $3)
         (i32.const 16)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $3)
     )
    )
    (br_if $label$6
     (i32.eqz
      (tee_local $1
       (i32.load offset=40
        (get_local $9)
       )
      )
     )
    )
   )
   (block $label$14
    (block $label$15
     (br_if $label$15
      (i32.eq
       (tee_local $8
        (i32.load
         (tee_local $0
          (i32.add
           (i32.add
            (get_local $9)
            (i32.const 16)
           )
           (i32.const 28)
          )
         )
        )
       )
       (get_local $1)
      )
     )
     (loop $label$16
      (set_local $3
       (i32.load
        (tee_local $8
         (i32.add
          (get_local $8)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $8)
       (i32.const 0)
      )
      (block $label$17
       (br_if $label$17
        (i32.eqz
         (get_local $3)
        )
       )
       (block $label$18
        (br_if $label$18
         (i32.eqz
          (i32.and
           (i32.load8_u offset=20
            (get_local $3)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $3)
           (i32.const 28)
          )
         )
        )
       )
       (block $label$19
        (br_if $label$19
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $3)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $3)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $3)
       )
      )
      (br_if $label$16
       (i32.ne
        (get_local $1)
        (get_local $8)
       )
      )
     )
     (set_local $3
      (i32.load
       (i32.add
        (get_local $9)
        (i32.const 40)
       )
      )
     )
     (br $label$14)
    )
    (set_local $3
     (get_local $1)
    )
   )
   (i32.store
    (get_local $0)
    (get_local $1)
   )
   (call $_ZdlPv
    (get_local $3)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $9)
    (i32.const 96)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyEEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (set_local $6
   (tee_local $4
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $4)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (tee_local $1
         (call $action_data_size)
        )
       )
      )
      (br_if $label$2
       (i32.lt_u
        (get_local $1)
        (i32.const 513)
       )
      )
      (set_local $4
       (call $malloc
        (get_local $1)
       )
      )
      (br $label$1)
     )
     (set_local $4
      (i32.const 0)
     )
     (br $label$0)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $4
      (i32.sub
       (get_local $4)
       (i32.and
        (i32.add
         (get_local $1)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $4)
     (get_local $1)
    )
   )
  )
  (i64.store offset=8
   (get_local $6)
   (i64.const 0)
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $1)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $6)
     (i32.const 8)
    )
    (get_local $4)
    (i32.const 8)
   )
  )
  (set_local $3
   (i64.load offset=8
    (get_local $6)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $1)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $4)
   )
  )
  (i64.store offset=8
   (get_local $6)
   (get_local $3)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $5
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $5)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$vii)
   (get_local $1)
   (i32.add
    (get_local $6)
    (i32.const 8)
   )
   (get_local $5)
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $6)
    (i32.const 16)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp10updatepermERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_ (type $FUNCSIG$viiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i64)
  (local $5 i64)
  (local $6 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (call $require_auth
   (i64.load
    (get_local $0)
   )
  )
  (i64.store offset=24
   (get_local $6)
   (i64.const -1)
  )
  (i32.store offset=32
   (get_local $6)
   (i32.const 0)
  )
  (i64.store offset=8
   (get_local $6)
   (tee_local $4
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $6)
   (tee_local $5
    (i64.load
     (get_local $1)
    )
   )
  )
  (i32.store
   (i32.add
    (get_local $6)
    (i32.const 36)
   )
   (i32.const 0)
  )
  (i32.store
   (i32.add
    (get_local $6)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (set_local $0
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.lt_s
     (tee_local $1
      (call $db_find_i64
       (get_local $4)
       (get_local $5)
       (i64.const -3020373100446351360)
       (get_local $5)
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=32
      (tee_local $0
       (call $_ZNK5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $6)
         (i32.const 8)
        )
        (get_local $1)
       )
      )
     )
     (i32.add
      (get_local $6)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $1
    (i32.ne
     (get_local $0)
     (i32.const 0)
    )
   )
   (i32.const 1024)
  )
  (i32.store offset=4
   (get_local $6)
   (get_local $3)
  )
  (i32.store
   (get_local $6)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $1)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE6modifyIZNS2_10updatepermERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEESG_E3$_1EEvRKS3_yOT_
   (i32.add
    (get_local $6)
    (i32.const 8)
   )
   (get_local $0)
   (get_local $6)
  )
  (block $label$1
   (br_if $label$1
    (i32.eqz
     (tee_local $3
      (i32.load offset=32
       (get_local $6)
      )
     )
    )
   )
   (block $label$2
    (block $label$3
     (br_if $label$3
      (i32.eq
       (tee_local $2
        (i32.load
         (tee_local $1
          (i32.add
           (i32.add
            (get_local $6)
            (i32.const 8)
           )
           (i32.const 28)
          )
         )
        )
       )
       (get_local $3)
      )
     )
     (loop $label$4
      (set_local $0
       (i32.load
        (tee_local $2
         (i32.add
          (get_local $2)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $2)
       (i32.const 0)
      )
      (block $label$5
       (br_if $label$5
        (i32.eqz
         (get_local $0)
        )
       )
       (block $label$6
        (br_if $label$6
         (i32.eqz
          (i32.and
           (i32.load8_u offset=20
            (get_local $0)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (block $label$7
        (br_if $label$7
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $0)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $0)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $0)
       )
      )
      (br_if $label$4
       (i32.ne
        (get_local $3)
        (get_local $2)
       )
      )
     )
     (set_local $0
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 32)
       )
      )
     )
     (br $label$2)
    )
    (set_local $0
     (get_local $3)
    )
   )
   (i32.store
    (get_local $1)
    (get_local $3)
   )
   (call $_ZdlPv
    (get_local $0)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $6)
    (i32.const 48)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_EEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $3
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 64)
    )
   )
  )
  (i32.store offset=44
   (tee_local $2
    (get_local $3)
   )
   (get_local $0)
  )
  (i32.store offset=32
   (get_local $2)
   (i32.load
    (get_local $1)
   )
  )
  (i32.store offset=36
   (get_local $2)
   (i32.load offset=4
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (tee_local $0
         (call $action_data_size)
        )
       )
      )
      (br_if $label$2
       (i32.lt_u
        (get_local $0)
        (i32.const 513)
       )
      )
      (set_local $1
       (call $malloc
        (get_local $0)
       )
      )
      (br $label$1)
     )
     (set_local $1
      (i32.const 0)
     )
     (br $label$0)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $3)
       (i32.and
        (i32.add
         (get_local $0)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $0)
    )
   )
  )
  (i64.store
   (i32.add
    (get_local $2)
    (i32.const 16)
   )
   (i64.const 0)
  )
  (i64.store
   (i32.add
    (get_local $2)
    (i32.const 24)
   )
   (i64.const 0)
  )
  (i64.store
   (get_local $2)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $2)
   (i64.const 0)
  )
  (i32.store offset=56
   (get_local $2)
   (i32.add
    (get_local $1)
    (get_local $0)
   )
  )
  (i32.store offset=48
   (get_local $2)
   (get_local $1)
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $0)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $2)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=52
   (get_local $2)
   (i32.add
    (get_local $1)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $2)
     (i32.const 48)
    )
    (i32.add
     (get_local $2)
     (i32.const 8)
    )
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $2)
     (i32.const 48)
    )
    (i32.add
     (get_local $2)
     (i32.const 20)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $0)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (i32.store offset=52
   (get_local $2)
   (i32.add
    (get_local $2)
    (i32.const 32)
   )
  )
  (i32.store offset=48
   (get_local $2)
   (i32.add
    (get_local $2)
    (i32.const 44)
   )
  )
  (call $_ZN5boost4mp116detail16tuple_apply_implIRZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES6_JRKyRKNSt3__112basic_stringIcNS9_11char_traitsIcEENS9_9allocatorIcEEEESH_EEEbPT_MT0_FvDpT1_EEUlDpT_E_RNS9_5tupleIJySF_SF_EEEJLj0ELj1ELj2EEEEDTclclsr3stdE7forwardISI_Efp_Espclsr3stdE3getIXT1_EEclsr3stdE7forwardISK_Efp0_EEEEOSI_OSK_NS0_16integer_sequenceIjJXspT1_EEEE
   (i32.add
    (get_local $2)
    (i32.const 48)
   )
   (get_local $2)
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (i32.load8_u offset=20
       (get_local $2)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $2)
      (i32.const 28)
     )
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=8
       (get_local $2)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $2)
      (i32.const 16)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $2)
    (i32.const 64)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp10modifypermERKyS2_RKh (type $FUNCSIG$viiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i64)
  (local $5 i64)
  (local $6 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 80)
    )
   )
  )
  (call $require_auth
   (i64.load
    (get_local $1)
   )
  )
  (i64.store offset=24
   (get_local $6)
   (i64.const -1)
  )
  (i32.store offset=32
   (get_local $6)
   (i32.const 0)
  )
  (i64.store offset=8
   (get_local $6)
   (tee_local $4
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $6)
   (tee_local $5
    (i64.load
     (get_local $2)
    )
   )
  )
  (i32.store
   (i32.add
    (get_local $6)
    (i32.const 36)
   )
   (i32.const 0)
  )
  (i32.store
   (i32.add
    (i32.add
     (get_local $6)
     (i32.const 8)
    )
    (i32.const 32)
   )
   (i32.const 0)
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.le_s
        (tee_local $2
         (call $db_find_i64
          (get_local $4)
          (get_local $5)
          (i64.const -6147646961140207616)
          (i64.load
           (get_local $1)
          )
         )
        )
        (i32.const -1)
       )
      )
      (call $eosio_assert
       (i32.eq
        (i32.load offset=16
         (tee_local $2
          (call $_ZNK5eosio11multi_indexILy12299097112569344000EN21UnificationFoundation16unification_uapp11permrecordsEJEE31load_object_by_primary_iteratorEl
           (i32.add
            (get_local $6)
            (i32.const 8)
           )
           (get_local $2)
          )
         )
        )
        (i32.add
         (get_local $6)
         (i32.const 8)
        )
       )
       (i32.const 224)
      )
      (set_local $5
       (i64.load
        (get_local $0)
       )
      )
      (call $eosio_assert
       (i32.const 1)
       (i32.const 288)
      )
      (call $eosio_assert
       (i32.eq
        (i32.load offset=16
         (get_local $2)
        )
        (i32.add
         (get_local $6)
         (i32.const 8)
        )
       )
       (i32.const 336)
      )
      (call $eosio_assert
       (i64.eq
        (i64.load offset=8
         (get_local $6)
        )
        (call $current_receiver)
       )
       (i32.const 384)
      )
      (i32.store8 offset=8
       (get_local $2)
       (i32.load8_u
        (get_local $3)
       )
      )
      (set_local $4
       (i64.load
        (get_local $2)
       )
      )
      (call $eosio_assert
       (i32.const 1)
       (i32.const 448)
      )
      (call $eosio_assert
       (i32.const 1)
       (i32.const 512)
      )
      (drop
       (call $memcpy
        (i32.add
         (get_local $6)
         (i32.const 64)
        )
        (get_local $2)
        (i32.const 8)
       )
      )
      (call $eosio_assert
       (i32.const 1)
       (i32.const 512)
      )
      (drop
       (call $memcpy
        (i32.or
         (i32.add
          (get_local $6)
          (i32.const 64)
         )
         (i32.const 8)
        )
        (i32.add
         (get_local $2)
         (i32.const 8)
        )
        (i32.const 1)
       )
      )
      (call $db_update_i64
       (i32.load offset=20
        (get_local $2)
       )
       (get_local $5)
       (i32.add
        (get_local $6)
        (i32.const 64)
       )
       (i32.const 9)
      )
      (br_if $label$2
       (i64.lt_u
        (get_local $4)
        (i64.load
         (tee_local $2
          (i32.add
           (get_local $6)
           (i32.const 24)
          )
         )
        )
       )
      )
      (i64.store
       (get_local $2)
       (select
        (i64.const -2)
        (i64.add
         (get_local $4)
         (i64.const 1)
        )
        (i64.gt_u
         (get_local $4)
         (i64.const -3)
        )
       )
      )
      (br_if $label$1
       (tee_local $0
        (i32.load offset=32
         (get_local $6)
        )
       )
      )
      (br $label$0)
     )
     (set_local $5
      (i64.load
       (get_local $0)
      )
     )
     (call $eosio_assert
      (i64.eq
       (i64.load offset=8
        (get_local $6)
       )
       (call $current_receiver)
      )
      (i32.const 160)
     )
     (i32.store offset=16
      (tee_local $2
       (call $_Znwj
        (i32.const 32)
       )
      )
      (i32.add
       (get_local $6)
       (i32.const 8)
      )
     )
     (i64.store
      (get_local $2)
      (i64.load
       (get_local $1)
      )
     )
     (i32.store8 offset=8
      (get_local $2)
      (i32.load8_u
       (get_local $3)
      )
     )
     (call $eosio_assert
      (i32.const 1)
      (i32.const 512)
     )
     (drop
      (call $memcpy
       (i32.add
        (get_local $6)
        (i32.const 64)
       )
       (get_local $2)
       (i32.const 8)
      )
     )
     (call $eosio_assert
      (i32.const 1)
      (i32.const 512)
     )
     (drop
      (call $memcpy
       (i32.or
        (i32.add
         (get_local $6)
         (i32.const 64)
        )
        (i32.const 8)
       )
       (i32.add
        (get_local $2)
        (i32.const 8)
       )
       (i32.const 1)
      )
     )
     (i32.store offset=20
      (get_local $2)
      (tee_local $0
       (call $db_store_i64
        (i64.load
         (i32.add
          (i32.add
           (get_local $6)
           (i32.const 8)
          )
          (i32.const 8)
         )
        )
        (i64.const -6147646961140207616)
        (get_local $5)
        (tee_local $4
         (i64.load
          (get_local $2)
         )
        )
        (i32.add
         (get_local $6)
         (i32.const 64)
        )
        (i32.const 9)
       )
      )
     )
     (block $label$4
      (br_if $label$4
       (i64.lt_u
        (get_local $4)
        (i64.load
         (tee_local $1
          (i32.add
           (get_local $6)
           (i32.const 24)
          )
         )
        )
       )
      )
      (i64.store
       (get_local $1)
       (select
        (i64.const -2)
        (i64.add
         (get_local $4)
         (i64.const 1)
        )
        (i64.gt_u
         (get_local $4)
         (i64.const -3)
        )
       )
      )
     )
     (i32.store offset=56
      (get_local $6)
      (get_local $2)
     )
     (i64.store offset=64
      (get_local $6)
      (tee_local $4
       (i64.load
        (get_local $2)
       )
      )
     )
     (i32.store offset=52
      (get_local $6)
      (get_local $0)
     )
     (block $label$5
      (block $label$6
       (br_if $label$6
        (i32.ge_u
         (tee_local $1
          (i32.load
           (tee_local $3
            (i32.add
             (get_local $6)
             (i32.const 36)
            )
           )
          )
         )
         (i32.load
          (i32.add
           (get_local $6)
           (i32.const 40)
          )
         )
        )
       )
       (i64.store offset=8
        (get_local $1)
        (get_local $4)
       )
       (i32.store offset=16
        (get_local $1)
        (get_local $0)
       )
       (i32.store offset=56
        (get_local $6)
        (i32.const 0)
       )
       (i32.store
        (get_local $1)
        (get_local $2)
       )
       (i32.store
        (get_local $3)
        (i32.add
         (get_local $1)
         (i32.const 24)
        )
       )
       (br $label$5)
      )
      (call $_ZNSt3__16vectorIN5eosio11multi_indexILy12299097112569344000EN21UnificationFoundation16unification_uapp11permrecordsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
       (i32.add
        (get_local $6)
        (i32.const 32)
       )
       (i32.add
        (get_local $6)
        (i32.const 56)
       )
       (i32.add
        (get_local $6)
        (i32.const 64)
       )
       (i32.add
        (get_local $6)
        (i32.const 52)
       )
      )
     )
     (set_local $2
      (i32.load offset=56
       (get_local $6)
      )
     )
     (i32.store offset=56
      (get_local $6)
      (i32.const 0)
     )
     (br_if $label$2
      (i32.eqz
       (get_local $2)
      )
     )
     (call $_ZdlPv
      (get_local $2)
     )
    )
    (br_if $label$0
     (i32.eqz
      (tee_local $0
       (i32.load offset=32
        (get_local $6)
       )
      )
     )
    )
   )
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.eq
       (tee_local $2
        (i32.load
         (tee_local $3
          (i32.add
           (get_local $6)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$9
      (set_local $1
       (i32.load
        (tee_local $2
         (i32.add
          (get_local $2)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $2)
       (i32.const 0)
      )
      (block $label$10
       (br_if $label$10
        (i32.eqz
         (get_local $1)
        )
       )
       (call $_ZdlPv
        (get_local $1)
       )
      )
      (br_if $label$9
       (i32.ne
        (get_local $0)
        (get_local $2)
       )
      )
     )
     (set_local $2
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 32)
       )
      )
     )
     (br $label$7)
    )
    (set_local $2
     (get_local $0)
    )
   )
   (i32.store
    (get_local $3)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $2)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $6)
    (i32.const 80)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKhEEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (set_local $7
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $6
   (i32.load
    (get_local $1)
   )
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $1
      (call $action_data_size)
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.lt_u
       (get_local $1)
       (i32.const 513)
      )
     )
     (set_local $5
      (call $malloc
       (get_local $1)
      )
     )
     (br $label$1)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $5
      (i32.sub
       (get_local $8)
       (i32.and
        (i32.add
         (get_local $1)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $5)
     (get_local $1)
    )
   )
  )
  (i64.store offset=8
   (get_local $7)
   (i64.const 0)
  )
  (i64.store
   (get_local $7)
   (i64.const 0)
  )
  (i32.store8 offset=16
   (get_local $7)
   (i32.const 0)
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $1)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $7)
    (get_local $5)
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.and
     (get_local $1)
     (i32.const -8)
    )
    (i32.const 8)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (tee_local $8
     (i32.add
      (get_local $7)
      (i32.const 8)
     )
    )
    (i32.add
     (get_local $5)
     (i32.const 8)
    )
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.ne
    (get_local $1)
    (i32.const 16)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (tee_local $3
     (i32.add
      (get_local $7)
      (i32.const 16)
     )
    )
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
    (i32.const 1)
   )
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $1)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $5)
   )
  )
  (set_local $1
   (i32.load8_u
    (get_local $3)
   )
  )
  (set_local $4
   (i64.load
    (get_local $8)
   )
  )
  (i64.store offset=40
   (get_local $7)
   (i64.load
    (get_local $7)
   )
  )
  (i64.store offset=32
   (get_local $7)
   (get_local $4)
  )
  (i32.store8 offset=31
   (get_local $7)
   (get_local $1)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $6
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $6)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiii)
   (get_local $1)
   (i32.add
    (get_local $7)
    (i32.const 40)
   )
   (i32.add
    (get_local $7)
    (i32.const 32)
   )
   (i32.add
    (get_local $7)
    (i32.const 31)
   )
   (get_local $6)
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 48)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp9addschemaERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEERKhSB_SB_SB_ (type $FUNCSIG$viiiiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32) (param $4 i32) (param $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (local $9 i64)
  (local $10 i64)
  (local $11 i64)
  (local $12 i64)
  (local $13 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $13
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 112)
    )
   )
  )
  (call $prints
   (i32.const 1008)
  )
  (call $eosio_assert
   (i32.lt_u
    (i32.and
     (i32.add
      (i32.load8_u
       (get_local $3)
      )
      (i32.const -1)
     )
     (i32.const 255)
    )
    (i32.const 3)
   )
   (i32.const 896)
  )
  (call $eosio_assert
   (i32.eq
    (i32.and
     (i32.or
      (i32.load8_u
       (get_local $2)
      )
      (i32.const 1)
     )
     (i32.const 255)
    )
    (i32.const 1)
   )
   (i32.const 960)
  )
  (set_local $6
   (i64.load
    (get_local $0)
   )
  )
  (set_local $10
   (i64.const 0)
  )
  (set_local $9
   (i64.const 59)
  )
  (set_local $2
   (i32.const 848)
  )
  (set_local $11
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $10)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $7
             (i32.load8_s
              (get_local $2)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $7
         (i32.add
          (get_local $7)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $12
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $10)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $7
       (select
        (i32.add
         (get_local $7)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $7)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $12
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $7)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $12
     (i64.shl
      (i64.and
       (get_local $12)
       (i64.const 31)
      )
      (i64.and
       (get_local $9)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $2
    (i32.add
     (get_local $2)
     (i32.const 1)
    )
   )
   (set_local $10
    (i64.add
     (get_local $10)
     (i64.const 1)
    )
   )
   (set_local $11
    (i64.or
     (get_local $12)
     (get_local $11)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $9
      (i64.add
       (get_local $9)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $6)
   (get_local $11)
  )
  (i32.store
   (tee_local $8
    (i32.add
     (get_local $13)
     (i32.const 64)
    )
   )
   (i32.const 0)
  )
  (i64.store offset=48
   (get_local $13)
   (i64.const -1)
  )
  (i64.store offset=56
   (get_local $13)
   (i64.const 0)
  )
  (i64.store offset=32
   (get_local $13)
   (tee_local $10
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=40
   (get_local $13)
   (get_local $10)
  )
  (i32.store offset=12
   (get_local $13)
   (get_local $1)
  )
  (i32.store offset=16
   (get_local $13)
   (get_local $3)
  )
  (i32.store offset=20
   (get_local $13)
   (get_local $4)
  )
  (i32.store offset=24
   (get_local $13)
   (get_local $5)
  )
  (i32.store offset=8
   (get_local $13)
   (i32.add
    (get_local $13)
    (i32.const 32)
   )
  )
  (i64.store offset=104
   (get_local $13)
   (get_local $10)
  )
  (call $eosio_assert
   (i64.eq
    (get_local $10)
    (call $current_receiver)
   )
   (i32.const 160)
  )
  (i32.store offset=84
   (get_local $13)
   (i32.add
    (get_local $13)
    (i32.const 8)
   )
  )
  (i32.store offset=80
   (get_local $13)
   (i32.add
    (get_local $13)
    (i32.const 32)
   )
  )
  (i32.store offset=88
   (get_local $13)
   (i32.add
    (get_local $13)
    (i32.const 104)
   )
  )
  (i32.store offset=16
   (tee_local $2
    (call $_Znwj
     (i32.const 40)
    )
   )
   (i32.const 0)
  )
  (i64.store offset=8 align=4
   (get_local $2)
   (i64.const 0)
  )
  (i32.store offset=24
   (get_local $2)
   (i32.add
    (get_local $13)
    (i32.const 32)
   )
  )
  (call $_ZZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE7emplaceIZNS2_9addschemaERKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEERKhSG_SG_SG_E3$_4EENS4_14const_iteratorEyOT_ENKUlRSJ_E_clINS4_4itemEEEDaSL_
   (i32.add
    (get_local $13)
    (i32.const 80)
   )
   (get_local $2)
  )
  (i32.store offset=96
   (get_local $13)
   (get_local $2)
  )
  (i64.store offset=80
   (get_local $13)
   (tee_local $10
    (i64.load
     (get_local $2)
    )
   )
  )
  (i32.store offset=76
   (get_local $13)
   (tee_local $0
    (i32.load offset=28
     (get_local $2)
    )
   )
  )
  (block $label$6
   (block $label$7
    (br_if $label$7
     (i32.ge_u
      (tee_local $7
       (i32.load
        (tee_local $3
         (i32.add
          (get_local $13)
          (i32.const 60)
         )
        )
       )
      )
      (i32.load
       (get_local $8)
      )
     )
    )
    (i64.store offset=8
     (get_local $7)
     (get_local $10)
    )
    (i32.store offset=16
     (get_local $7)
     (get_local $0)
    )
    (i32.store offset=96
     (get_local $13)
     (i32.const 0)
    )
    (i32.store
     (get_local $7)
     (get_local $2)
    )
    (i32.store
     (get_local $3)
     (i32.add
      (get_local $7)
      (i32.const 24)
     )
    )
    (br $label$6)
   )
   (call $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
    (i32.add
     (get_local $13)
     (i32.const 56)
    )
    (i32.add
     (get_local $13)
     (i32.const 96)
    )
    (i32.add
     (get_local $13)
     (i32.const 80)
    )
    (i32.add
     (get_local $13)
     (i32.const 76)
    )
   )
  )
  (set_local $2
   (i32.load offset=96
    (get_local $13)
   )
  )
  (i32.store offset=96
   (get_local $13)
   (i32.const 0)
  )
  (block $label$8
   (br_if $label$8
    (i32.eqz
     (get_local $2)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=8
        (get_local $2)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $2)
       (i32.const 16)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $2)
   )
  )
  (block $label$10
   (br_if $label$10
    (i32.eqz
     (tee_local $0
      (i32.load offset=56
       (get_local $13)
      )
     )
    )
   )
   (block $label$11
    (block $label$12
     (br_if $label$12
      (i32.eq
       (tee_local $2
        (i32.load
         (tee_local $3
          (i32.add
           (get_local $13)
           (i32.const 60)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$13
      (set_local $7
       (i32.load
        (tee_local $2
         (i32.add
          (get_local $2)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $2)
       (i32.const 0)
      )
      (block $label$14
       (br_if $label$14
        (i32.eqz
         (get_local $7)
        )
       )
       (block $label$15
        (br_if $label$15
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $7)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $7)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $7)
       )
      )
      (br_if $label$13
       (i32.ne
        (get_local $0)
        (get_local $2)
       )
      )
     )
     (set_local $2
      (i32.load
       (i32.add
        (get_local $13)
        (i32.const 56)
       )
      )
     )
     (br $label$11)
    )
    (set_local $2
     (get_local $0)
    )
   )
   (i32.store
    (get_local $3)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $2)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $13)
    (i32.const 112)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_EEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (set_local $5
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $6)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $4
   (i32.load
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (tee_local $3
         (call $action_data_size)
        )
       )
      )
      (br_if $label$2
       (i32.lt_u
        (get_local $3)
        (i32.const 513)
       )
      )
      (set_local $1
       (call $malloc
        (get_local $3)
       )
      )
      (br $label$1)
     )
     (set_local $1
      (i32.const 0)
     )
     (br $label$0)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $6)
       (i32.and
        (i32.add
         (get_local $3)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $3)
    )
   )
  )
  (i64.store
   (get_local $5)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $5)
   (i64.const 0)
  )
  (i32.store offset=36
   (get_local $5)
   (get_local $1)
  )
  (i32.store offset=32
   (get_local $5)
   (get_local $1)
  )
  (i32.store offset=40
   (get_local $5)
   (i32.add
    (get_local $1)
    (get_local $3)
   )
  )
  (i32.store offset=16
   (get_local $5)
   (i32.add
    (get_local $5)
    (i32.const 32)
   )
  )
  (i32.store offset=24
   (get_local $5)
   (get_local $5)
  )
  (call $_ZN5boost6fusion6detail17for_each_unrolledILi5EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhhhhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJSD_hhhhEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_
   (i32.add
    (get_local $5)
    (i32.const 24)
   )
   (i32.add
    (get_local $5)
    (i32.const 16)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $5)
     (i32.const 32)
    )
    (get_local $5)
   )
  )
  (set_local $1
   (i32.load8_u
    (i32.add
     (get_local $5)
     (i32.const 15)
    )
   )
  )
  (set_local $3
   (i32.load8_u
    (i32.add
     (get_local $5)
     (i32.const 14)
    )
   )
  )
  (set_local $6
   (i32.load8_u
    (i32.add
     (get_local $5)
     (i32.const 13)
    )
   )
  )
  (i32.store8 offset=24
   (get_local $5)
   (i32.load8_u
    (i32.add
     (get_local $5)
     (i32.const 12)
    )
   )
  )
  (i32.store8 offset=16
   (get_local $5)
   (get_local $6)
  )
  (i32.store8 offset=47
   (get_local $5)
   (get_local $3)
  )
  (i32.store8 offset=46
   (get_local $5)
   (get_local $1)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $4
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $4)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiiiii)
   (get_local $1)
   (i32.add
    (get_local $5)
    (i32.const 32)
   )
   (i32.add
    (get_local $5)
    (i32.const 24)
   )
   (i32.add
    (get_local $5)
    (i32.const 16)
   )
   (i32.add
    (get_local $5)
    (i32.const 47)
   )
   (i32.add
    (get_local $5)
    (i32.const 46)
   )
   (get_local $4)
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=32
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=40
     (get_local $5)
    )
   )
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (i32.and
      (i32.load8_u
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $5)
      (i32.const 8)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $5)
    (i32.const 48)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp10editschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERKhSD_SD_SD_ (type $FUNCSIG$viiiiiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32) (param $4 i32) (param $5 i32) (param $6 i32)
  (local $7 i64)
  (local $8 i32)
  (local $9 i32)
  (local $10 i64)
  (local $11 i64)
  (local $12 i64)
  (local $13 i64)
  (local $14 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $14
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 64)
    )
   )
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (set_local $11
   (i64.const 0)
  )
  (set_local $10
   (i64.const 59)
  )
  (set_local $9
   (i32.const 848)
  )
  (set_local $12
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $11)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $8
             (i32.load8_s
              (get_local $9)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $8
         (i32.add
          (get_local $8)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $13
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $11)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $8
       (select
        (i32.add
         (get_local $8)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $8)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $13
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $8)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $13
     (i64.shl
      (i64.and
       (get_local $13)
       (i64.const 31)
      )
      (i64.and
       (get_local $10)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $9
    (i32.add
     (get_local $9)
     (i32.const 1)
    )
   )
   (set_local $11
    (i64.add
     (get_local $11)
     (i64.const 1)
    )
   )
   (set_local $12
    (i64.or
     (get_local $13)
     (get_local $12)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $10
      (i64.add
       (get_local $10)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $7)
   (get_local $12)
  )
  (call $eosio_assert
   (i32.lt_u
    (i32.and
     (i32.add
      (i32.load8_u
       (get_local $4)
      )
      (i32.const -1)
     )
     (i32.const 255)
    )
    (i32.const 3)
   )
   (i32.const 896)
  )
  (call $eosio_assert
   (i32.eq
    (i32.and
     (i32.or
      (i32.load8_u
       (get_local $3)
      )
      (i32.const 1)
     )
     (i32.const 255)
    )
    (i32.const 1)
   )
   (i32.const 960)
  )
  (i32.store
   (i32.add
    (get_local $14)
    (i32.const 56)
   )
   (i32.const 0)
  )
  (i64.store offset=40
   (get_local $14)
   (i64.const -1)
  )
  (i64.store offset=48
   (get_local $14)
   (i64.const 0)
  )
  (i64.store offset=24
   (get_local $14)
   (tee_local $11
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=32
   (get_local $14)
   (get_local $11)
  )
  (set_local $9
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $8
      (call $db_find_i64
       (get_local $11)
       (get_local $11)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $9
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $14)
         (i32.const 24)
        )
        (get_local $8)
       )
      )
     )
     (i32.add
      (get_local $14)
      (i32.const 24)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $8
    (i32.ne
     (get_local $9)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $11
   (i64.load
    (get_local $0)
   )
  )
  (i32.store offset=4
   (get_local $14)
   (get_local $4)
  )
  (i32.store
   (get_local $14)
   (get_local $2)
  )
  (i32.store offset=8
   (get_local $14)
   (get_local $3)
  )
  (i32.store offset=12
   (get_local $14)
   (get_local $5)
  )
  (i32.store offset=16
   (get_local $14)
   (get_local $6)
  )
  (call $eosio_assert
   (get_local $8)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_10editschemaERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEERKhSI_SI_SI_E3$_5EEvRKS3_yOT_
   (i32.add
    (get_local $14)
    (i32.const 24)
   )
   (get_local $9)
   (get_local $11)
   (get_local $14)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=48
       (get_local $14)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $9
        (i32.load
         (tee_local $3
          (i32.add
           (get_local $14)
           (i32.const 52)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $8
       (i32.load
        (tee_local $9
         (i32.add
          (get_local $9)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $9)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $8)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $8)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $8)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $8)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $9)
       )
      )
     )
     (set_local $9
      (i32.load
       (i32.add
        (get_local $14)
        (i32.const 48)
       )
      )
     )
     (br $label$8)
    )
    (set_local $9
     (get_local $0)
    )
   )
   (i32.store
    (get_local $3)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $9)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $14)
    (i32.const 64)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERKhSF_SF_SF_EEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (set_local $7
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 64)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $6
   (i32.load
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (tee_local $3
         (call $action_data_size)
        )
       )
      )
      (br_if $label$2
       (i32.lt_u
        (get_local $3)
        (i32.const 513)
       )
      )
      (set_local $1
       (call $malloc
        (get_local $3)
       )
      )
      (br $label$1)
     )
     (set_local $1
      (i32.const 0)
     )
     (br $label$0)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $8)
       (i32.and
        (i32.add
         (get_local $3)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $3)
    )
   )
  )
  (i64.store
   (i32.add
    (get_local $7)
    (i32.const 24)
   )
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $7)
   (i64.const 0)
  )
  (i64.store offset=16
   (get_local $7)
   (i64.const 0)
  )
  (i32.store offset=44
   (get_local $7)
   (get_local $1)
  )
  (i32.store offset=40
   (get_local $7)
   (get_local $1)
  )
  (i32.store offset=48
   (get_local $7)
   (i32.add
    (get_local $1)
    (get_local $3)
   )
  )
  (i32.store offset=32
   (get_local $7)
   (i32.add
    (get_local $7)
    (i32.const 40)
   )
  )
  (i32.store offset=56
   (get_local $7)
   (i32.add
    (get_local $7)
    (i32.const 8)
   )
  )
  (call $_ZN5boost6fusion6detail17for_each_unrolledILi6EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJyNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhhhhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJySD_hhhhEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_
   (i32.add
    (get_local $7)
    (i32.const 56)
   )
   (i32.add
    (get_local $7)
    (i32.const 32)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (set_local $4
   (i64.load offset=8
    (get_local $7)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $7)
     (i32.const 40)
    )
    (i32.add
     (get_local $7)
     (i32.const 16)
    )
   )
  )
  (set_local $1
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 31)
    )
   )
  )
  (set_local $3
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 30)
    )
   )
  )
  (set_local $8
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 29)
    )
   )
  )
  (set_local $5
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 28)
    )
   )
  )
  (i64.store offset=56
   (get_local $7)
   (get_local $4)
  )
  (i32.store8 offset=32
   (get_local $7)
   (get_local $5)
  )
  (i32.store8 offset=55
   (get_local $7)
   (get_local $8)
  )
  (i32.store8 offset=54
   (get_local $7)
   (get_local $3)
  )
  (i32.store8 offset=53
   (get_local $7)
   (get_local $1)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $6
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $6)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiiiiii)
   (get_local $1)
   (i32.add
    (get_local $7)
    (i32.const 56)
   )
   (i32.add
    (get_local $7)
    (i32.const 40)
   )
   (i32.add
    (get_local $7)
    (i32.const 32)
   )
   (i32.add
    (get_local $7)
    (i32.const 55)
   )
   (i32.add
    (get_local $7)
    (i32.const 54)
   )
   (i32.add
    (get_local $7)
    (i32.const 53)
   )
   (get_local $6)
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=40
       (get_local $7)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=48
     (get_local $7)
    )
   )
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (i32.and
      (i32.load8_u offset=16
       (get_local $7)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $7)
      (i32.const 24)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 64)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp7setversERKyRKh (type $FUNCSIG$viii) (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $3
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 848)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $4
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $4
         (i32.add
          (get_local $4)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $4
       (select
        (i32.add
         (get_local $4)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $4)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $4)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $3)
   (get_local $8)
  )
  (call $eosio_assert
   (i32.eq
    (i32.and
     (i32.or
      (i32.load8_u
       (get_local $2)
      )
      (i32.const 1)
     )
     (i32.const 255)
    )
    (i32.const 1)
   )
   (i32.const 960)
  )
  (i32.store
   (i32.add
    (get_local $10)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $10)
   (get_local $7)
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $4
      (call $db_find_i64
       (get_local $7)
       (get_local $7)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $5
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $10)
         (i32.const 8)
        )
        (get_local $4)
       )
      )
     )
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $4
    (i32.ne
     (get_local $5)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (i32.store
   (get_local $10)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $4)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_7setversERKyRKhE3$_6EEvRKS3_yOT_
   (i32.add
    (get_local $10)
    (i32.const 8)
   )
   (get_local $5)
   (get_local $7)
   (get_local $10)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=32
       (get_local $10)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $2
          (i32.add
           (get_local $10)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $4
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $4)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $4)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $4)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $4)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 32)
       )
      )
     )
     (br $label$8)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $2)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 48)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKhEEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (set_local $5
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 32)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $6)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $4
   (i32.load
    (get_local $1)
   )
  )
  (set_local $3
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $1
      (call $action_data_size)
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.lt_u
       (get_local $1)
       (i32.const 513)
      )
     )
     (set_local $3
      (call $malloc
       (get_local $1)
      )
     )
     (br $label$1)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $3
      (i32.sub
       (get_local $6)
       (i32.and
        (i32.add
         (get_local $1)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $3)
     (get_local $1)
    )
   )
  )
  (i32.store8 offset=8
   (get_local $5)
   (i32.const 0)
  )
  (i64.store
   (get_local $5)
   (i64.const 0)
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $1)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $5)
    (get_local $3)
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.ne
    (get_local $1)
    (i32.const 8)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (tee_local $6
     (i32.add
      (get_local $5)
      (i32.const 8)
     )
    )
    (i32.add
     (get_local $3)
     (i32.const 8)
    )
    (i32.const 1)
   )
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $1)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $3)
   )
  )
  (set_local $1
   (i32.load8_u
    (get_local $6)
   )
  )
  (i64.store offset=24
   (get_local $5)
   (i64.load
    (get_local $5)
   )
  )
  (i32.store8 offset=23
   (get_local $5)
   (get_local $1)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $4
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $4)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viii)
   (get_local $1)
   (i32.add
    (get_local $5)
    (i32.const 24)
   )
   (i32.add
    (get_local $5)
    (i32.const 23)
   )
   (get_local $4)
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $5)
    (i32.const 32)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp11setscheduleERKyRKh (type $FUNCSIG$viii) (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $3
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 848)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $4
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $4
         (i32.add
          (get_local $4)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $4
       (select
        (i32.add
         (get_local $4)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $4)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $4)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $3)
   (get_local $8)
  )
  (call $eosio_assert
   (i32.lt_u
    (i32.and
     (i32.add
      (i32.load8_u
       (get_local $2)
      )
      (i32.const -1)
     )
     (i32.const 255)
    )
    (i32.const 3)
   )
   (i32.const 896)
  )
  (i32.store
   (i32.add
    (get_local $10)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $10)
   (get_local $7)
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $4
      (call $db_find_i64
       (get_local $7)
       (get_local $7)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $5
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $10)
         (i32.const 8)
        )
        (get_local $4)
       )
      )
     )
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $4
    (i32.ne
     (get_local $5)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (i32.store
   (get_local $10)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $4)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setscheduleERKyRKhE3$_7EEvRKS3_yOT_
   (i32.add
    (get_local $10)
    (i32.const 8)
   )
   (get_local $5)
   (get_local $7)
   (get_local $10)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=32
       (get_local $10)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $2
          (i32.add
           (get_local $10)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $4
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $4)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $4)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $4)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $4)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 32)
       )
      )
     )
     (br $label$8)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $2)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 48)
   )
  )
 )
 (func $_ZN21UnificationFoundation16unification_uapp11setpriceschERKyRKh (type $FUNCSIG$viii) (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $3
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 848)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $4
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $4
         (i32.add
          (get_local $4)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $4
       (select
        (i32.add
         (get_local $4)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $4)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $4)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $3)
   (get_local $8)
  )
  (i32.store
   (i32.add
    (get_local $10)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $10)
   (get_local $7)
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $4
      (call $db_find_i64
       (get_local $7)
       (get_local $7)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $5
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $10)
         (i32.const 8)
        )
        (get_local $4)
       )
      )
     )
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $4
    (i32.ne
     (get_local $5)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (i32.store
   (get_local $10)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $4)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setpriceschERKyRKhE3$_8EEvRKS3_yOT_
   (i32.add
    (get_local $10)
    (i32.const 8)
   )
   (get_local $5)
   (get_local $7)
   (get_local $10)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=32
       (get_local $10)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $10)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $4
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $4)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $4)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $4)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $4)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 32)
       )
      )
     )
     (br $label$8)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $1)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 48)
   )
  )
 )
 (func $_ZN21UnificationFoundation16unification_uapp11setpriceadhERKyRKh (type $FUNCSIG$viii) (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $3
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 848)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $4
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $4
         (i32.add
          (get_local $4)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $4
       (select
        (i32.add
         (get_local $4)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $4)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $4)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $3)
   (get_local $8)
  )
  (i32.store
   (i32.add
    (get_local $10)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $10)
   (get_local $7)
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $4
      (call $db_find_i64
       (get_local $7)
       (get_local $7)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $5
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $10)
         (i32.const 8)
        )
        (get_local $4)
       )
      )
     )
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $4
    (i32.ne
     (get_local $5)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (i32.store
   (get_local $10)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $4)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setpriceadhERKyRKhE3$_9EEvRKS3_yOT_
   (i32.add
    (get_local $10)
    (i32.const 8)
   )
   (get_local $5)
   (get_local $7)
   (get_local $10)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=32
       (get_local $10)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $10)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $4
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $4)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $4)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $4)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $4)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 32)
       )
      )
     )
     (br $label$8)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $1)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 48)
   )
  )
 )
 (func $_ZN21UnificationFoundation16unification_uapp9setschemaERKyRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE (type $FUNCSIG$viii) (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $3
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 848)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $4
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $4
         (i32.add
          (get_local $4)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $4
       (select
        (i32.add
         (get_local $4)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $4)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $4)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $3)
   (get_local $8)
  )
  (i32.store
   (i32.add
    (get_local $10)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $10)
   (get_local $7)
  )
  (set_local $5
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $4
      (call $db_find_i64
       (get_local $7)
       (get_local $7)
       (i64.const 5310425802474631168)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=24
      (tee_local $5
       (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $10)
         (i32.const 8)
        )
        (get_local $4)
       )
      )
     )
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $4
    (i32.ne
     (get_local $5)
     (i32.const 0)
    )
   )
   (i32.const 864)
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (i32.store
   (get_local $10)
   (get_local $2)
  )
  (call $eosio_assert
   (get_local $4)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_9setschemaERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEEE4$_10EEvRKS3_yOT_
   (i32.add
    (get_local $10)
    (i32.const 8)
   )
   (get_local $5)
   (get_local $7)
   (get_local $10)
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (tee_local $0
      (i32.load offset=32
       (get_local $10)
      )
     )
    )
   )
   (block $label$8
    (block $label$9
     (br_if $label$9
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $10)
           (i32.const 36)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$10
      (set_local $4
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$11
       (br_if $label$11
        (i32.eqz
         (get_local $4)
        )
       )
       (block $label$12
        (br_if $label$12
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $4)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $4)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $4)
       )
      )
      (br_if $label$10
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 32)
       )
      )
     )
     (br $label$8)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $1)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 48)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEEEEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (set_local $6
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (set_local $1
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $3
      (call $action_data_size)
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.lt_u
       (get_local $3)
       (i32.const 513)
      )
     )
     (set_local $1
      (call $malloc
       (get_local $3)
      )
     )
     (br $label$1)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $7)
       (i32.and
        (i32.add
         (get_local $3)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $3)
    )
   )
  )
  (i32.store
   (i32.add
    (get_local $6)
    (i32.const 16)
   )
   (i32.const 0)
  )
  (i64.store
   (get_local $6)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $6)
   (i64.const 0)
  )
  (i32.store offset=32
   (get_local $6)
   (i32.add
    (get_local $1)
    (get_local $3)
   )
  )
  (i32.store offset=24
   (get_local $6)
   (get_local $1)
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $3)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $6)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=28
   (get_local $6)
   (i32.add
    (get_local $1)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $6)
     (i32.const 24)
    )
    (tee_local $7
     (i32.add
      (get_local $6)
      (i32.const 8)
     )
    )
   )
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (set_local $4
   (i64.load
    (get_local $6)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $6)
     (i32.const 24)
    )
    (get_local $7)
   )
  )
  (i64.store offset=40
   (get_local $6)
   (get_local $4)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $5
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $5)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viii)
   (get_local $1)
   (i32.add
    (get_local $6)
    (i32.const 40)
   )
   (i32.add
    (get_local $6)
    (i32.const 24)
   )
   (get_local $5)
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (i32.load8_u offset=24
       (get_local $6)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=32
     (get_local $6)
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=8
       (get_local $6)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $6)
      (i32.const 16)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $6)
    (i32.const 48)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp7initreqERKyS2_RKhRKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEES4_ (type $FUNCSIG$viiiiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32) (param $4 i32) (param $5 i32)
  (local $6 i32)
  (local $7 i64)
  (local $8 i64)
  (local $9 i32)
  (local $10 i32)
  (local $11 i64)
  (local $12 i64)
  (local $13 i64)
  (local $14 i64)
  (local $15 i64)
  (local $16 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $16
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 128)
    )
   )
  )
  (set_local $15
   (i64.load
    (get_local $0)
   )
  )
  (set_local $12
   (i64.const 0)
  )
  (set_local $11
   (i64.const 59)
  )
  (set_local $10
   (i32.const 736)
  )
  (set_local $13
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $12)
          (i64.const 5)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $6
             (i32.load8_s
              (get_local $10)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $6
         (i32.add
          (get_local $6)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $14
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $12)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $6
       (select
        (i32.add
         (get_local $6)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $6)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $14
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $6)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $14
     (i64.shl
      (i64.and
       (get_local $14)
       (i64.const 31)
      )
      (i64.and
       (get_local $11)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $10
    (i32.add
     (get_local $10)
     (i32.const 1)
    )
   )
   (set_local $12
    (i64.add
     (get_local $12)
     (i64.const 1)
    )
   )
   (set_local $13
    (i64.or
     (get_local $14)
     (get_local $13)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $11
      (i64.add
       (get_local $11)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $15)
   (get_local $13)
  )
  (i32.store
   (tee_local $9
    (i32.add
     (get_local $16)
     (i32.const 80)
    )
   )
   (i32.const 0)
  )
  (i64.store offset=64
   (get_local $16)
   (i64.const -1)
  )
  (i64.store offset=72
   (get_local $16)
   (i64.const 0)
  )
  (i64.store offset=48
   (get_local $16)
   (tee_local $12
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=56
   (get_local $16)
   (get_local $12)
  )
  (i32.store offset=12
   (get_local $16)
   (get_local $1)
  )
  (i32.store offset=16
   (get_local $16)
   (get_local $2)
  )
  (i32.store offset=20
   (get_local $16)
   (get_local $3)
  )
  (i32.store offset=24
   (get_local $16)
   (get_local $4)
  )
  (i32.store offset=28
   (get_local $16)
   (get_local $5)
  )
  (i32.store offset=8
   (get_local $16)
   (i32.add
    (get_local $16)
    (i32.const 48)
   )
  )
  (i64.store offset=104
   (get_local $16)
   (get_local $12)
  )
  (call $eosio_assert
   (i64.eq
    (get_local $12)
    (call $current_receiver)
   )
   (i32.const 160)
  )
  (i32.store offset=116
   (get_local $16)
   (i32.add
    (get_local $16)
    (i32.const 8)
   )
  )
  (i32.store offset=112
   (get_local $16)
   (i32.add
    (get_local $16)
    (i32.const 48)
   )
  )
  (i32.store offset=120
   (get_local $16)
   (i32.add
    (get_local $16)
    (i32.const 104)
   )
  )
  (i32.store offset=36
   (tee_local $10
    (call $_Znwj
     (i32.const 80)
    )
   )
   (i32.const 0)
  )
  (i64.store offset=28 align=4
   (get_local $10)
   (i64.const 0)
  )
  (i32.store offset=44
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=48
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=52
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=56
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=60
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=64
   (get_local $10)
   (i32.const 0)
  )
  (i32.store offset=68
   (get_local $10)
   (i32.add
    (get_local $16)
    (i32.const 48)
   )
  )
  (call $_ZZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE7emplaceIZNS2_7initreqERKyS7_RKhRKNSt3__112basic_stringIcNSA_11char_traitsIcEENSA_9allocatorIcEEEES9_E4$_11EENS4_14const_iteratorEyOT_ENKUlRSL_E_clINS4_4itemEEEDaSN_
   (i32.add
    (get_local $16)
    (i32.const 112)
   )
   (get_local $10)
  )
  (i32.store offset=96
   (get_local $16)
   (get_local $10)
  )
  (i64.store offset=112
   (get_local $16)
   (tee_local $12
    (i64.load
     (get_local $10)
    )
   )
  )
  (i32.store offset=92
   (get_local $16)
   (tee_local $2
    (i32.load offset=72
     (get_local $10)
    )
   )
  )
  (block $label$6
   (block $label$7
    (br_if $label$7
     (i32.ge_u
      (tee_local $6
       (i32.load
        (tee_local $3
         (i32.add
          (get_local $16)
          (i32.const 76)
         )
        )
       )
      )
      (i32.load
       (get_local $9)
      )
     )
    )
    (i64.store offset=8
     (get_local $6)
     (get_local $12)
    )
    (i32.store offset=16
     (get_local $6)
     (get_local $2)
    )
    (i32.store offset=96
     (get_local $16)
     (i32.const 0)
    )
    (i32.store
     (get_local $6)
     (get_local $10)
    )
    (i32.store
     (get_local $3)
     (i32.add
      (get_local $6)
      (i32.const 24)
     )
    )
    (br $label$6)
   )
   (call $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
    (i32.add
     (get_local $16)
     (i32.const 72)
    )
    (i32.add
     (get_local $16)
     (i32.const 96)
    )
    (i32.add
     (get_local $16)
     (i32.const 112)
    )
    (i32.add
     (get_local $16)
     (i32.const 92)
    )
   )
  )
  (set_local $10
   (i32.load offset=96
    (get_local $16)
   )
  )
  (i32.store offset=96
   (get_local $16)
   (i32.const 0)
  )
  (block $label$8
   (br_if $label$8
    (i32.eqz
     (get_local $10)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=56
        (get_local $10)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $10)
       (i32.const 64)
      )
     )
    )
   )
   (block $label$10
    (br_if $label$10
     (i32.eqz
      (i32.and
       (i32.load8_u offset=44
        (get_local $10)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $10)
       (i32.const 52)
      )
     )
    )
   )
   (block $label$11
    (br_if $label$11
     (i32.eqz
      (i32.and
       (i32.load8_u offset=28
        (get_local $10)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $10)
       (i32.const 36)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $10)
   )
  )
  (set_local $7
   (i64.load
    (get_local $0)
   )
  )
  (set_local $12
   (i64.const 0)
  )
  (set_local $11
   (i64.const 59)
  )
  (set_local $10
   (i32.const 736)
  )
  (set_local $13
   (i64.const 0)
  )
  (loop $label$12
   (block $label$13
    (block $label$14
     (block $label$15
      (block $label$16
       (block $label$17
        (br_if $label$17
         (i64.gt_u
          (get_local $12)
          (i64.const 5)
         )
        )
        (br_if $label$16
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $6
             (i32.load8_s
              (get_local $10)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $6
         (i32.add
          (get_local $6)
          (i32.const 165)
         )
        )
        (br $label$15)
       )
       (set_local $14
        (i64.const 0)
       )
       (br_if $label$14
        (i64.le_u
         (get_local $12)
         (i64.const 11)
        )
       )
       (br $label$13)
      )
      (set_local $6
       (select
        (i32.add
         (get_local $6)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $6)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $14
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $6)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $14
     (i64.shl
      (i64.and
       (get_local $14)
       (i64.const 31)
      )
      (i64.and
       (get_local $11)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $10
    (i32.add
     (get_local $10)
     (i32.const 1)
    )
   )
   (set_local $12
    (i64.add
     (get_local $12)
     (i64.const 1)
    )
   )
   (set_local $13
    (i64.or
     (get_local $14)
     (get_local $13)
    )
   )
   (br_if $label$12
    (i64.ne
     (tee_local $11
      (i64.add
       (get_local $11)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (set_local $8
   (i64.load
    (get_local $1)
   )
  )
  (set_local $12
   (i64.const 0)
  )
  (set_local $11
   (i64.const 59)
  )
  (set_local $10
   (i32.const 832)
  )
  (set_local $15
   (i64.const 0)
  )
  (loop $label$18
   (block $label$19
    (block $label$20
     (block $label$21
      (block $label$22
       (block $label$23
        (br_if $label$23
         (i64.gt_u
          (get_local $12)
          (i64.const 7)
         )
        )
        (br_if $label$22
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $6
             (i32.load8_s
              (get_local $10)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $6
         (i32.add
          (get_local $6)
          (i32.const 165)
         )
        )
        (br $label$21)
       )
       (set_local $14
        (i64.const 0)
       )
       (br_if $label$20
        (i64.le_u
         (get_local $12)
         (i64.const 11)
        )
       )
       (br $label$19)
      )
      (set_local $6
       (select
        (i32.add
         (get_local $6)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $6)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $14
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $6)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $14
     (i64.shl
      (i64.and
       (get_local $14)
       (i64.const 31)
      )
      (i64.and
       (get_local $11)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $10
    (i32.add
     (get_local $10)
     (i32.const 1)
    )
   )
   (set_local $12
    (i64.add
     (get_local $12)
     (i64.const 1)
    )
   )
   (set_local $15
    (i64.or
     (get_local $14)
     (get_local $15)
    )
   )
   (br_if $label$18
    (i64.ne
     (tee_local $11
      (i64.add
       (get_local $11)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (i64.store offset=16
   (get_local $16)
   (get_local $15)
  )
  (i64.store offset=8
   (get_local $16)
   (get_local $8)
  )
  (i64.store
   (tee_local $10
    (call $_Znwj
     (i32.const 16)
    )
   )
   (get_local $7)
  )
  (i64.store offset=8
   (get_local $10)
   (get_local $13)
  )
  (i32.store
   (tee_local $6
    (i32.add
     (get_local $16)
     (i32.const 40)
    )
   )
   (i32.const 0)
  )
  (i32.store
   (i32.add
    (get_local $16)
    (i32.const 32)
   )
   (tee_local $1
    (i32.add
     (get_local $10)
     (i32.const 16)
    )
   )
  )
  (i32.store
   (i32.add
    (get_local $16)
    (i32.const 28)
   )
   (get_local $1)
  )
  (i32.store offset=24
   (get_local $16)
   (get_local $10)
  )
  (i32.store offset=36
   (get_local $16)
   (i32.const 0)
  )
  (i32.store
   (i32.add
    (get_local $16)
    (i32.const 44)
   )
   (i32.const 0)
  )
  (call $_ZNSt3__16vectorIcNS_9allocatorIcEEE8__appendEj
   (i32.add
    (get_local $16)
    (i32.const 36)
   )
   (i32.const 8)
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load
      (get_local $6)
     )
     (tee_local $10
      (i32.load offset=36
       (get_local $16)
      )
     )
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $10)
    (get_local $0)
    (i32.const 8)
   )
  )
  (call $_ZN5eosio4packINS_6actionEEENSt3__16vectorIcNS2_9allocatorIcEEEERKT_
   (i32.add
    (get_local $16)
    (i32.const 112)
   )
   (i32.add
    (get_local $16)
    (i32.const 8)
   )
  )
  (call $send_inline
   (tee_local $10
    (i32.load offset=112
     (get_local $16)
    )
   )
   (i32.sub
    (i32.load offset=116
     (get_local $16)
    )
    (get_local $10)
   )
  )
  (block $label$24
   (br_if $label$24
    (i32.eqz
     (tee_local $10
      (i32.load offset=112
       (get_local $16)
      )
     )
    )
   )
   (i32.store offset=116
    (get_local $16)
    (get_local $10)
   )
   (call $_ZdlPv
    (get_local $10)
   )
  )
  (block $label$25
   (br_if $label$25
    (i32.eqz
     (tee_local $10
      (i32.load offset=36
       (get_local $16)
      )
     )
    )
   )
   (i32.store
    (i32.add
     (get_local $16)
     (i32.const 40)
    )
    (get_local $10)
   )
   (call $_ZdlPv
    (get_local $10)
   )
  )
  (block $label$26
   (br_if $label$26
    (i32.eqz
     (tee_local $10
      (i32.load offset=24
       (get_local $16)
      )
     )
    )
   )
   (i32.store
    (i32.add
     (get_local $16)
     (i32.const 28)
    )
    (get_local $10)
   )
   (call $_ZdlPv
    (get_local $10)
   )
  )
  (drop
   (call $_ZNSt3__113__vector_baseIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEED2Ev
    (i32.add
     (get_local $16)
     (i32.const 72)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $16)
    (i32.const 128)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKhRKNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEES6_EEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i64)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (set_local $7
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 80)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $6
   (i32.load
    (get_local $1)
   )
  )
  (set_local $1
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $3
      (call $action_data_size)
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.lt_u
       (get_local $3)
       (i32.const 513)
      )
     )
     (set_local $1
      (call $malloc
       (get_local $3)
      )
     )
     (br $label$1)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $8)
       (i32.and
        (i32.add
         (get_local $3)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $3)
    )
   )
  )
  (i32.store
   (i32.add
    (get_local $7)
    (i32.const 36)
   )
   (i32.const 0)
  )
  (i64.store offset=16
   (get_local $7)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $7)
   (i64.const 0)
  )
  (i32.store8 offset=24
   (get_local $7)
   (i32.const 0)
  )
  (i64.store offset=28 align=4
   (get_local $7)
   (i64.const 0)
  )
  (i32.store8 offset=40
   (get_local $7)
   (i32.const 0)
  )
  (i32.store offset=52
   (get_local $7)
   (get_local $1)
  )
  (i32.store offset=48
   (get_local $7)
   (get_local $1)
  )
  (i32.store offset=56
   (get_local $7)
   (i32.add
    (get_local $1)
    (get_local $3)
   )
  )
  (i32.store offset=64
   (get_local $7)
   (i32.add
    (get_local $7)
    (i32.const 48)
   )
  )
  (i32.store offset=72
   (get_local $7)
   (i32.add
    (get_local $7)
    (i32.const 8)
   )
  )
  (call $_ZN5boost6fusion6detail17for_each_unrolledILi5EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJyyhNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJyyhSD_hEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_
   (i32.add
    (get_local $7)
    (i32.const 72)
   )
   (i32.add
    (get_local $7)
    (i32.const 64)
   )
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (set_local $1
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 24)
    )
   )
  )
  (set_local $4
   (i64.load
    (i32.add
     (get_local $7)
     (i32.const 16)
    )
   )
  )
  (set_local $5
   (i64.load offset=8
    (get_local $7)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $7)
     (i32.const 48)
    )
    (i32.add
     (get_local $7)
     (i32.const 28)
    )
   )
  )
  (set_local $3
   (i32.load8_u
    (i32.add
     (get_local $7)
     (i32.const 40)
    )
   )
  )
  (i64.store offset=72
   (get_local $7)
   (get_local $5)
  )
  (i64.store offset=64
   (get_local $7)
   (get_local $4)
  )
  (i32.store8 offset=63
   (get_local $7)
   (get_local $1)
  )
  (i32.store8 offset=62
   (get_local $7)
   (get_local $3)
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $6
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $6)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiiiii)
   (get_local $1)
   (i32.add
    (get_local $7)
    (i32.const 72)
   )
   (i32.add
    (get_local $7)
    (i32.const 64)
   )
   (i32.add
    (get_local $7)
    (i32.const 63)
   )
   (i32.add
    (get_local $7)
    (i32.const 48)
   )
   (i32.add
    (get_local $7)
    (i32.const 62)
   )
   (get_local $6)
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (i32.load8_u offset=48
       (get_local $7)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=56
     (get_local $7)
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=28
       (get_local $7)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $7)
      (i32.const 36)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 80)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp9updatereqERKyS2_RKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEESB_ (type $FUNCSIG$viiiii) (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32) (param $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i64)
  (local $9 i64)
  (local $10 i64)
  (local $11 i64)
  (local $12 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $12
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $5
   (i64.load
    (get_local $2)
   )
  )
  (set_local $9
   (i64.const 0)
  )
  (set_local $8
   (i64.const 59)
  )
  (set_local $7
   (i32.const 736)
  )
  (set_local $10
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $9)
          (i64.const 5)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $6
             (i32.load8_s
              (get_local $7)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $6
         (i32.add
          (get_local $6)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $11
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $9)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $6
       (select
        (i32.add
         (get_local $6)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $6)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $11
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $6)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $11
     (i64.shl
      (i64.and
       (get_local $11)
       (i64.const 31)
      )
      (i64.and
       (get_local $8)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $7
    (i32.add
     (get_local $7)
     (i32.const 1)
    )
   )
   (set_local $9
    (i64.add
     (get_local $9)
     (i64.const 1)
    )
   )
   (set_local $10
    (i64.or
     (get_local $11)
     (get_local $10)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $8
      (i64.add
       (get_local $8)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $5)
   (get_local $10)
  )
  (i32.store
   (i32.add
    (get_local $12)
    (i32.const 40)
   )
   (i32.const 0)
  )
  (i64.store offset=24
   (get_local $12)
   (i64.const -1)
  )
  (i64.store offset=32
   (get_local $12)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $12)
   (tee_local $9
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=16
   (get_local $12)
   (get_local $9)
  )
  (set_local $7
   (i32.const 0)
  )
  (block $label$6
   (br_if $label$6
    (i32.lt_s
     (tee_local $6
      (call $db_find_i64
       (get_local $9)
       (get_local $9)
       (i64.const 5310425292135727104)
       (i64.load
        (get_local $1)
       )
      )
     )
     (i32.const 0)
    )
   )
   (call $eosio_assert
    (i32.eq
     (i32.load offset=68
      (tee_local $7
       (call $_ZNK5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE31load_object_by_primary_iteratorEl
        (i32.add
         (get_local $12)
         (i32.const 8)
        )
        (get_local $6)
       )
      )
     )
     (i32.add
      (get_local $12)
      (i32.const 8)
     )
    )
    (i32.const 224)
   )
  )
  (call $eosio_assert
   (tee_local $6
    (i32.ne
     (get_local $7)
     (i32.const 0)
    )
   )
   (i32.const 752)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load offset=8
     (get_local $7)
    )
    (i64.load
     (get_local $2)
    )
   )
   (i32.const 784)
  )
  (set_local $9
   (i64.load
    (get_local $0)
   )
  )
  (i32.store offset=4
   (get_local $12)
   (get_local $4)
  )
  (i32.store
   (get_local $12)
   (get_local $3)
  )
  (call $eosio_assert
   (get_local $6)
   (i32.const 288)
  )
  (call $_ZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE6modifyIZNS2_9updatereqERKyS7_RKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEESG_E4$_12EEvRKS3_yOT_
   (i32.add
    (get_local $12)
    (i32.const 8)
   )
   (get_local $7)
   (get_local $9)
   (get_local $12)
  )
  (drop
   (call $_ZNSt3__113__vector_baseIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEED2Ev
    (i32.add
     (get_local $12)
     (i32.const 32)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $12)
    (i32.const 48)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JRKyS4_RKNSt3__112basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_EEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $4
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 80)
    )
   )
  )
  (i32.store offset=60
   (tee_local $3
    (get_local $4)
   )
   (get_local $0)
  )
  (i32.store offset=48
   (get_local $3)
   (i32.load
    (get_local $1)
   )
  )
  (i32.store offset=52
   (get_local $3)
   (i32.load offset=4
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (tee_local $0
         (call $action_data_size)
        )
       )
      )
      (br_if $label$2
       (i32.lt_u
        (get_local $0)
        (i32.const 513)
       )
      )
      (set_local $1
       (call $malloc
        (get_local $0)
       )
      )
      (br $label$1)
     )
     (set_local $1
      (i32.const 0)
     )
     (br $label$0)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $4)
       (i32.and
        (i32.add
         (get_local $0)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $0)
    )
   )
  )
  (i64.store
   (i32.add
    (get_local $3)
    (i32.const 32)
   )
   (i64.const 0)
  )
  (i64.store
   (i32.add
    (get_local $3)
    (i32.const 40)
   )
   (i64.const 0)
  )
  (i64.store offset=16
   (get_local $3)
   (i64.const 0)
  )
  (i64.store offset=8
   (get_local $3)
   (i64.const 0)
  )
  (i64.store offset=24
   (get_local $3)
   (i64.const 0)
  )
  (i32.store offset=64
   (get_local $3)
   (get_local $1)
  )
  (i32.store offset=72
   (get_local $3)
   (tee_local $4
    (i32.add
     (get_local $1)
     (get_local $0)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (get_local $0)
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $3)
     (i32.const 8)
    )
    (get_local $1)
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (get_local $4)
     (tee_local $2
      (i32.add
       (get_local $1)
       (i32.const 8)
      )
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (i32.add
      (get_local $3)
      (i32.const 8)
     )
     (i32.const 8)
    )
    (get_local $2)
    (i32.const 8)
   )
  )
  (i32.store offset=68
   (get_local $3)
   (i32.add
    (get_local $1)
    (i32.const 16)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $3)
     (i32.const 64)
    )
    (i32.add
     (i32.add
      (get_local $3)
      (i32.const 8)
     )
     (i32.const 16)
    )
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $3)
     (i32.const 64)
    )
    (i32.add
     (get_local $3)
     (i32.const 36)
    )
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $0)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (i32.store offset=68
   (get_local $3)
   (i32.add
    (get_local $3)
    (i32.const 48)
   )
  )
  (i32.store offset=64
   (get_local $3)
   (i32.add
    (get_local $3)
    (i32.const 60)
   )
  )
  (call $_ZN5boost4mp116detail16tuple_apply_implIRZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES6_JRKyS8_RKNSt3__112basic_stringIcNS9_11char_traitsIcEENS9_9allocatorIcEEEESH_EEEbPT_MT0_FvDpT1_EEUlDpT_E_RNS9_5tupleIJyySF_SF_EEEJLj0ELj1ELj2ELj3EEEEDTclclsr3stdE7forwardISI_Efp_Espclsr3stdE3getIXT1_EEclsr3stdE7forwardISK_Efp0_EEEEOSI_OSK_NS0_16integer_sequenceIjJXspT1_EEEE
   (i32.add
    (get_local $3)
    (i32.const 64)
   )
   (i32.add
    (get_local $3)
    (i32.const 8)
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (i32.load8_u offset=36
       (get_local $3)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $3)
      (i32.const 44)
     )
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=24
       (get_local $3)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $3)
      (i32.const 32)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $3)
    (i32.const 80)
   )
  )
  (i32.const 1)
 )
 (func $_ZN21UnificationFoundation16unification_uapp9setrsakeyENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE (type $FUNCSIG$vii) (param $0 i32) (param $1 i32)
  (local $2 i64)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i64)
  (local $8 i64)
  (local $9 i64)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 96)
    )
   )
  )
  (set_local $2
   (i64.load
    (get_local $0)
   )
  )
  (set_local $7
   (i64.const 0)
  )
  (set_local $6
   (i64.const 59)
  )
  (set_local $5
   (i32.const 144)
  )
  (set_local $8
   (i64.const 0)
  )
  (loop $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (br_if $label$5
         (i64.gt_u
          (get_local $7)
          (i64.const 8)
         )
        )
        (br_if $label$4
         (i32.gt_u
          (i32.and
           (i32.add
            (tee_local $3
             (i32.load8_s
              (get_local $5)
             )
            )
            (i32.const -97)
           )
           (i32.const 255)
          )
          (i32.const 25)
         )
        )
        (set_local $3
         (i32.add
          (get_local $3)
          (i32.const 165)
         )
        )
        (br $label$3)
       )
       (set_local $9
        (i64.const 0)
       )
       (br_if $label$2
        (i64.le_u
         (get_local $7)
         (i64.const 11)
        )
       )
       (br $label$1)
      )
      (set_local $3
       (select
        (i32.add
         (get_local $3)
         (i32.const 208)
        )
        (i32.const 0)
        (i32.lt_u
         (i32.and
          (i32.add
           (get_local $3)
           (i32.const -49)
          )
          (i32.const 255)
         )
         (i32.const 5)
        )
       )
      )
     )
     (set_local $9
      (i64.shr_s
       (i64.shl
        (i64.extend_u/i32
         (get_local $3)
        )
        (i64.const 56)
       )
       (i64.const 56)
      )
     )
    )
    (set_local $9
     (i64.shl
      (i64.and
       (get_local $9)
       (i64.const 31)
      )
      (i64.and
       (get_local $6)
       (i64.const 4294967295)
      )
     )
    )
   )
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (set_local $7
    (i64.add
     (get_local $7)
     (i64.const 1)
    )
   )
   (set_local $8
    (i64.or
     (get_local $9)
     (get_local $8)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.add
       (get_local $6)
       (i64.const -5)
      )
     )
     (i64.const -6)
    )
   )
  )
  (call $require_auth2
   (get_local $2)
   (get_local $8)
  )
  (i32.store
   (tee_local $3
    (i32.add
     (i32.add
      (get_local $10)
      (i32.const 16)
     )
     (i32.const 32)
    )
   )
   (i32.const 0)
  )
  (i64.store offset=32
   (get_local $10)
   (i64.const -1)
  )
  (i64.store offset=16
   (get_local $10)
   (tee_local $7
    (i64.load
     (get_local $0)
    )
   )
  )
  (i64.store offset=24
   (get_local $10)
   (get_local $7)
  )
  (i64.store offset=40
   (get_local $10)
   (i64.const 0)
  )
  (block $label$6
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.le_s
       (tee_local $5
        (call $db_find_i64
         (get_local $7)
         (get_local $7)
         (i64.const -4752039648192102400)
         (i64.const 0)
        )
       )
       (i32.const -1)
      )
     )
     (call $eosio_assert
      (i32.eq
       (i32.load offset=20
        (tee_local $5
         (call $_ZNK5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE31load_object_by_primary_iteratorEl
          (i32.add
           (get_local $10)
           (i32.const 16)
          )
          (get_local $5)
         )
        )
       )
       (i32.add
        (get_local $10)
        (i32.const 16)
       )
      )
      (i32.const 224)
     )
     (set_local $7
      (i64.load
       (get_local $0)
      )
     )
     (i32.store offset=64
      (get_local $10)
      (get_local $1)
     )
     (call $eosio_assert
      (i32.const 1)
      (i32.const 288)
     )
     (call $_ZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE6modifyIZNS2_9setrsakeyENSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEE4$_14EEvRKS3_yOT_
      (i32.add
       (get_local $10)
       (i32.const 16)
      )
      (get_local $5)
      (get_local $7)
      (i32.add
       (get_local $10)
       (i32.const 64)
      )
     )
     (br_if $label$7
      (tee_local $0
       (i32.load offset=40
        (get_local $10)
       )
      )
     )
     (br $label$6)
    )
    (set_local $7
     (i64.load
      (get_local $0)
     )
    )
    (i32.store offset=12
     (get_local $10)
     (get_local $1)
    )
    (i32.store offset=8
     (get_local $10)
     (i32.add
      (get_local $10)
      (i32.const 16)
     )
    )
    (i64.store offset=88
     (get_local $10)
     (get_local $7)
    )
    (call $eosio_assert
     (i64.eq
      (i64.load offset=16
       (get_local $10)
      )
      (call $current_receiver)
     )
     (i32.const 160)
    )
    (i32.store offset=68
     (get_local $10)
     (i32.add
      (get_local $10)
      (i32.const 8)
     )
    )
    (i32.store offset=64
     (get_local $10)
     (i32.add
      (get_local $10)
      (i32.const 16)
     )
    )
    (i32.store offset=72
     (get_local $10)
     (i32.add
      (get_local $10)
      (i32.const 88)
     )
    )
    (i32.store offset=16
     (tee_local $5
      (call $_Znwj
       (i32.const 32)
      )
     )
     (i32.const 0)
    )
    (i64.store offset=8 align=4
     (get_local $5)
     (i64.const 0)
    )
    (i32.store offset=20
     (get_local $5)
     (i32.add
      (get_local $10)
      (i32.const 16)
     )
    )
    (call $_ZZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE7emplaceIZNS2_9setrsakeyENSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEE4$_13EENS4_14const_iteratorEyOT_ENKUlRSF_E_clINS4_4itemEEEDaSH_
     (i32.add
      (get_local $10)
      (i32.const 64)
     )
     (get_local $5)
    )
    (i32.store offset=80
     (get_local $10)
     (get_local $5)
    )
    (i64.store offset=64
     (get_local $10)
     (tee_local $7
      (i64.load
       (get_local $5)
      )
     )
    )
    (i32.store offset=60
     (get_local $10)
     (tee_local $1
      (i32.load offset=24
       (get_local $5)
      )
     )
    )
    (block $label$9
     (block $label$10
      (br_if $label$10
       (i32.ge_u
        (tee_local $0
         (i32.load
          (tee_local $4
           (i32.add
            (get_local $10)
            (i32.const 44)
           )
          )
         )
        )
        (i32.load
         (get_local $3)
        )
       )
      )
      (i64.store offset=8
       (get_local $0)
       (get_local $7)
      )
      (i32.store offset=16
       (get_local $0)
       (get_local $1)
      )
      (i32.store offset=80
       (get_local $10)
       (i32.const 0)
      )
      (i32.store
       (get_local $0)
       (get_local $5)
      )
      (i32.store
       (get_local $4)
       (i32.add
        (get_local $0)
        (i32.const 24)
       )
      )
      (br $label$9)
     )
     (call $_ZNSt3__16vectorIN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
      (i32.add
       (get_local $10)
       (i32.const 40)
      )
      (i32.add
       (get_local $10)
       (i32.const 80)
      )
      (i32.add
       (get_local $10)
       (i32.const 64)
      )
      (i32.add
       (get_local $10)
       (i32.const 60)
      )
     )
    )
    (set_local $5
     (i32.load offset=80
      (get_local $10)
     )
    )
    (i32.store offset=80
     (get_local $10)
     (i32.const 0)
    )
    (block $label$11
     (br_if $label$11
      (i32.eqz
       (get_local $5)
      )
     )
     (block $label$12
      (br_if $label$12
       (i32.eqz
        (i32.and
         (i32.load8_u offset=8
          (get_local $5)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $5)
         (i32.const 16)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $5)
     )
    )
    (br_if $label$6
     (i32.eqz
      (tee_local $0
       (i32.load offset=40
        (get_local $10)
       )
      )
     )
    )
   )
   (block $label$13
    (block $label$14
     (br_if $label$14
      (i32.eq
       (tee_local $5
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $10)
           (i32.const 44)
          )
         )
        )
       )
       (get_local $0)
      )
     )
     (loop $label$15
      (set_local $3
       (i32.load
        (tee_local $5
         (i32.add
          (get_local $5)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.const 0)
      )
      (block $label$16
       (br_if $label$16
        (i32.eqz
         (get_local $3)
        )
       )
       (block $label$17
        (br_if $label$17
         (i32.eqz
          (i32.and
           (i32.load8_u offset=8
            (get_local $3)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $3)
           (i32.const 16)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $3)
       )
      )
      (br_if $label$15
       (i32.ne
        (get_local $0)
        (get_local $5)
       )
      )
     )
     (set_local $5
      (i32.load
       (i32.add
        (get_local $10)
        (i32.const 40)
       )
      )
     )
     (br $label$13)
    )
    (set_local $5
     (get_local $0)
    )
   )
   (i32.store
    (get_local $1)
    (get_local $0)
   )
   (call $_ZdlPv
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 96)
   )
  )
 )
 (func $_ZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES2_JNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEEEEbPT_MT0_FvDpT1_E (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (set_local $5
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $6)
  )
  (set_local $2
   (i32.load offset=4
    (get_local $1)
   )
  )
  (set_local $4
   (i32.load
    (get_local $1)
   )
  )
  (set_local $1
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $3
      (call $action_data_size)
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.lt_u
       (get_local $3)
       (i32.const 513)
      )
     )
     (set_local $1
      (call $malloc
       (get_local $3)
      )
     )
     (br $label$1)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $1
      (i32.sub
       (get_local $6)
       (i32.and
        (i32.add
         (get_local $3)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $read_action_data
     (get_local $1)
     (get_local $3)
    )
   )
  )
  (i32.store offset=8
   (get_local $5)
   (i32.const 0)
  )
  (i64.store
   (get_local $5)
   (i64.const 0)
  )
  (i32.store offset=36
   (get_local $5)
   (get_local $1)
  )
  (i32.store offset=32
   (get_local $5)
   (get_local $1)
  )
  (i32.store offset=40
   (get_local $5)
   (i32.add
    (get_local $1)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.add
     (get_local $5)
     (i32.const 32)
    )
    (get_local $5)
   )
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $1)
   )
  )
  (set_local $1
   (i32.add
    (get_local $0)
    (i32.shr_s
     (get_local $2)
     (i32.const 1)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
    (get_local $5)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.eqz
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
   (set_local $4
    (i32.load
     (i32.add
      (i32.load
       (get_local $1)
      )
      (get_local $4)
     )
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $5)
     (i32.const 32)
    )
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
   )
  )
  (call_indirect (type $FUNCSIG$vii)
   (get_local $1)
   (i32.add
    (get_local $5)
    (i32.const 32)
   )
   (get_local $4)
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (i32.and
      (i32.load8_u offset=32
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=40
     (get_local $5)
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (i32.and
      (i32.load8_u offset=16
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=24
     (get_local $5)
    )
   )
  )
  (block $label$7
   (br_if $label$7
    (i32.eqz
     (i32.and
      (i32.load8_u
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load
     (i32.add
      (get_local $5)
      (i32.const 8)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $5)
    (i32.const 48)
   )
  )
  (i32.const 1)
 )
 (func $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 32)
    )
   )
  )
  (i32.store offset=24
   (get_local $7)
   (i32.const 0)
  )
  (i64.store offset=16
   (get_local $7)
   (i64.const 0)
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__16vectorIcNS7_9allocatorIcEEEE
    (get_local $0)
    (i32.add
     (get_local $7)
     (i32.const 16)
    )
   )
  )
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (block $label$5
        (block $label$6
         (block $label$7
          (block $label$8
           (br_if $label$8
            (i32.ne
             (tee_local $5
              (i32.load offset=20
               (get_local $7)
              )
             )
             (tee_local $4
              (i32.load offset=16
               (get_local $7)
              )
             )
            )
           )
           (br_if $label$7
            (i32.and
             (i32.load8_u
              (get_local $1)
             )
             (i32.const 1)
            )
           )
           (i32.store16
            (get_local $1)
            (i32.const 0)
           )
           (set_local $4
            (i32.add
             (get_local $1)
             (i32.const 8)
            )
           )
           (br $label$6)
          )
          (i32.store
           (i32.add
            (get_local $7)
            (i32.const 8)
           )
           (i32.const 0)
          )
          (i64.store
           (get_local $7)
           (i64.const 0)
          )
          (br_if $label$0
           (i32.ge_u
            (tee_local $2
             (i32.sub
              (get_local $5)
              (get_local $4)
             )
            )
            (i32.const -16)
           )
          )
          (br_if $label$5
           (i32.ge_u
            (get_local $2)
            (i32.const 11)
           )
          )
          (i32.store8
           (get_local $7)
           (i32.shl
            (get_local $2)
            (i32.const 1)
           )
          )
          (set_local $6
           (i32.or
            (get_local $7)
            (i32.const 1)
           )
          )
          (br_if $label$4
           (get_local $2)
          )
          (br $label$3)
         )
         (i32.store8
          (i32.load offset=8
           (get_local $1)
          )
          (i32.const 0)
         )
         (i32.store offset=4
          (get_local $1)
          (i32.const 0)
         )
         (set_local $4
          (i32.add
           (get_local $1)
           (i32.const 8)
          )
         )
        )
        (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEj
         (get_local $1)
         (i32.const 0)
        )
        (i32.store
         (get_local $4)
         (i32.const 0)
        )
        (i64.store align=4
         (get_local $1)
         (i64.const 0)
        )
        (br_if $label$2
         (tee_local $4
          (i32.load offset=16
           (get_local $7)
          )
         )
        )
        (br $label$1)
       )
       (set_local $6
        (call $_Znwj
         (tee_local $5
          (i32.and
           (i32.add
            (get_local $2)
            (i32.const 16)
           )
           (i32.const -16)
          )
         )
        )
       )
       (i32.store
        (get_local $7)
        (i32.or
         (get_local $5)
         (i32.const 1)
        )
       )
       (i32.store offset=8
        (get_local $7)
        (get_local $6)
       )
       (i32.store offset=4
        (get_local $7)
        (get_local $2)
       )
      )
      (set_local $3
       (get_local $2)
      )
      (set_local $5
       (get_local $6)
      )
      (loop $label$9
       (i32.store8
        (get_local $5)
        (i32.load8_u
         (get_local $4)
        )
       )
       (set_local $5
        (i32.add
         (get_local $5)
         (i32.const 1)
        )
       )
       (set_local $4
        (i32.add
         (get_local $4)
         (i32.const 1)
        )
       )
       (br_if $label$9
        (tee_local $3
         (i32.add
          (get_local $3)
          (i32.const -1)
         )
        )
       )
      )
      (set_local $6
       (i32.add
        (get_local $6)
        (get_local $2)
       )
      )
     )
     (i32.store8
      (get_local $6)
      (i32.const 0)
     )
     (block $label$10
      (block $label$11
       (br_if $label$11
        (i32.and
         (i32.load8_u
          (get_local $1)
         )
         (i32.const 1)
        )
       )
       (i32.store16
        (get_local $1)
        (i32.const 0)
       )
       (br $label$10)
      )
      (i32.store8
       (i32.load offset=8
        (get_local $1)
       )
       (i32.const 0)
      )
      (i32.store offset=4
       (get_local $1)
       (i32.const 0)
      )
     )
     (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEj
      (get_local $1)
      (i32.const 0)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const 8)
      )
      (i32.load
       (i32.add
        (get_local $7)
        (i32.const 8)
       )
      )
     )
     (i64.store align=4
      (get_local $1)
      (i64.load
       (get_local $7)
      )
     )
     (br_if $label$1
      (i32.eqz
       (tee_local $4
        (i32.load offset=16
         (get_local $7)
        )
       )
      )
     )
    )
    (i32.store offset=20
     (get_local $7)
     (get_local $4)
    )
    (call $_ZdlPv
     (get_local $4)
    )
   )
   (i32.store offset=4
    (i32.const 0)
    (i32.add
     (get_local $7)
     (i32.const 32)
    )
   )
   (return
    (get_local $0)
   )
  )
  (call $_ZNKSt3__121__basic_string_commonILb1EE20__throw_length_errorEv
   (get_local $7)
  )
  (unreachable)
 )
 (func $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__16vectorIcNS7_9allocatorIcEEEE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (set_local $5
   (i32.load offset=4
    (get_local $0)
   )
  )
  (set_local $7
   (i32.const 0)
  )
  (set_local $6
   (i64.const 0)
  )
  (set_local $2
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
  )
  (set_local $3
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
  )
  (loop $label$0
   (call $eosio_assert
    (i32.lt_u
     (get_local $5)
     (i32.load
      (get_local $2)
     )
    )
    (i32.const 112)
   )
   (set_local $4
    (i32.load8_u
     (tee_local $5
      (i32.load
       (get_local $3)
      )
     )
    )
   )
   (i32.store
    (get_local $3)
    (tee_local $5
     (i32.add
      (get_local $5)
      (i32.const 1)
     )
    )
   )
   (set_local $6
    (i64.or
     (i64.extend_u/i32
      (i32.shl
       (i32.and
        (get_local $4)
        (i32.const 127)
       )
       (tee_local $7
        (i32.and
         (get_local $7)
         (i32.const 255)
        )
       )
      )
     )
     (get_local $6)
    )
   )
   (set_local $7
    (i32.add
     (get_local $7)
     (i32.const 7)
    )
   )
   (br_if $label$0
    (i32.shr_u
     (get_local $4)
     (i32.const 7)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.le_u
      (tee_local $3
       (i32.wrap/i64
        (get_local $6)
       )
      )
      (tee_local $2
       (i32.sub
        (tee_local $7
         (i32.load offset=4
          (get_local $1)
         )
        )
        (tee_local $4
         (i32.load
          (get_local $1)
         )
        )
       )
      )
     )
    )
    (call $_ZNSt3__16vectorIcNS_9allocatorIcEEE8__appendEj
     (get_local $1)
     (i32.sub
      (get_local $3)
      (get_local $2)
     )
    )
    (set_local $5
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $1)
       (i32.const 4)
      )
     )
    )
    (set_local $4
     (i32.load
      (get_local $1)
     )
    )
    (br $label$1)
   )
   (br_if $label$1
    (i32.ge_u
     (get_local $3)
     (get_local $2)
    )
   )
   (i32.store
    (i32.add
     (get_local $1)
     (i32.const 4)
    )
    (tee_local $7
     (i32.add
      (get_local $4)
      (get_local $3)
     )
    )
   )
  )
  (call $eosio_assert
   (i32.ge_u
    (i32.sub
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 8)
      )
     )
     (get_local $5)
    )
    (tee_local $5
     (i32.sub
      (get_local $7)
      (get_local $4)
     )
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $4)
    (i32.load
     (tee_local $7
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (get_local $5)
   )
  )
  (i32.store
   (get_local $7)
   (i32.add
    (i32.load
     (get_local $7)
    )
    (get_local $5)
   )
  )
  (get_local $0)
 )
 (func $_ZNSt3__16vectorIcNS_9allocatorIcEEE8__appendEj (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (block $label$4
       (br_if $label$4
        (i32.ge_u
         (i32.sub
          (tee_local $2
           (i32.load offset=8
            (get_local $0)
           )
          )
          (tee_local $6
           (i32.load offset=4
            (get_local $0)
           )
          )
         )
         (get_local $1)
        )
       )
       (br_if $label$2
        (i32.le_s
         (tee_local $4
          (i32.add
           (tee_local $3
            (i32.sub
             (get_local $6)
             (tee_local $5
              (i32.load
               (get_local $0)
              )
             )
            )
           )
           (get_local $1)
          )
         )
         (i32.const -1)
        )
       )
       (set_local $6
        (i32.const 2147483647)
       )
       (block $label$5
        (br_if $label$5
         (i32.gt_u
          (tee_local $2
           (i32.sub
            (get_local $2)
            (get_local $5)
           )
          )
          (i32.const 1073741822)
         )
        )
        (br_if $label$3
         (i32.eqz
          (tee_local $6
           (select
            (get_local $4)
            (tee_local $6
             (i32.shl
              (get_local $2)
              (i32.const 1)
             )
            )
            (i32.lt_u
             (get_local $6)
             (get_local $4)
            )
           )
          )
         )
        )
       )
       (set_local $2
        (call $_Znwj
         (get_local $6)
        )
       )
       (br $label$1)
      )
      (set_local $0
       (i32.add
        (get_local $0)
        (i32.const 4)
       )
      )
      (loop $label$6
       (i32.store8
        (get_local $6)
        (i32.const 0)
       )
       (i32.store
        (get_local $0)
        (tee_local $6
         (i32.add
          (i32.load
           (get_local $0)
          )
          (i32.const 1)
         )
        )
       )
       (br_if $label$6
        (tee_local $1
         (i32.add
          (get_local $1)
          (i32.const -1)
         )
        )
       )
       (br $label$0)
      )
     )
     (set_local $6
      (i32.const 0)
     )
     (set_local $2
      (i32.const 0)
     )
     (br $label$1)
    )
    (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
     (get_local $0)
    )
    (unreachable)
   )
   (set_local $4
    (i32.add
     (get_local $2)
     (get_local $6)
    )
   )
   (set_local $6
    (tee_local $5
     (i32.add
      (get_local $2)
      (get_local $3)
     )
    )
   )
   (loop $label$7
    (i32.store8
     (get_local $6)
     (i32.const 0)
    )
    (set_local $6
     (i32.add
      (get_local $6)
      (i32.const 1)
     )
    )
    (br_if $label$7
     (tee_local $1
      (i32.add
       (get_local $1)
       (i32.const -1)
      )
     )
    )
   )
   (set_local $5
    (i32.sub
     (get_local $5)
     (tee_local $2
      (i32.sub
       (i32.load
        (tee_local $3
         (i32.add
          (get_local $0)
          (i32.const 4)
         )
        )
       )
       (tee_local $1
        (i32.load
         (get_local $0)
        )
       )
      )
     )
    )
   )
   (block $label$8
    (br_if $label$8
     (i32.lt_s
      (get_local $2)
      (i32.const 1)
     )
    )
    (drop
     (call $memcpy
      (get_local $5)
      (get_local $1)
      (get_local $2)
     )
    )
    (set_local $1
     (i32.load
      (get_local $0)
     )
    )
   )
   (i32.store
    (get_local $0)
    (get_local $5)
   )
   (i32.store
    (get_local $3)
    (get_local $6)
   )
   (i32.store
    (i32.add
     (get_local $0)
     (i32.const 8)
    )
    (get_local $4)
   )
   (br_if $label$0
    (i32.eqz
     (get_local $1)
    )
   )
   (call $_ZdlPv
    (get_local $1)
   )
   (return)
  )
 )
 (func $_ZZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE7emplaceIZNS2_9setrsakeyENSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEE4$_13EENS4_14const_iteratorEyOT_ENKUlRSF_E_clINS4_4itemEEEDaSH_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (set_local $2
   (i32.load
    (get_local $0)
   )
  )
  (block $label$0
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.load offset=16
       (tee_local $5
        (i32.load
         (tee_local $3
          (i32.load offset=4
           (get_local $0)
          )
         )
        )
       )
      )
     )
     (i64.const -1)
    )
   )
   (set_local $6
    (i64.const 0)
   )
   (block $label$1
    (br_if $label$1
     (i32.lt_s
      (tee_local $4
       (call $db_lowerbound_i64
        (i64.load
         (get_local $5)
        )
        (i64.load offset=8
         (get_local $5)
        )
        (i64.const -4752039648192102400)
        (i64.const 0)
       )
      )
      (i32.const 0)
     )
    )
    (drop
     (call $_ZNK5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE31load_object_by_primary_iteratorEl
      (get_local $5)
      (get_local $4)
     )
    )
    (i32.store offset=4
     (get_local $8)
     (i32.const 0)
    )
    (i32.store
     (get_local $8)
     (get_local $5)
    )
    (set_local $6
     (select
      (i64.const -2)
      (i64.add
       (tee_local $6
        (i64.load
         (i32.load offset=4
          (call $_ZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE14const_iteratormmEv
           (get_local $8)
          )
         )
        )
       )
       (i64.const 1)
      )
      (i64.gt_u
       (get_local $6)
       (i64.const -3)
      )
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
    (get_local $6)
   )
  )
  (call $eosio_assert
   (i64.lt_u
    (get_local $6)
    (i64.const -2)
   )
   (i32.const 560)
  )
  (i64.store
   (get_local $1)
   (i64.load
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (tee_local $4
     (i32.add
      (get_local $1)
      (i32.const 8)
     )
    )
    (i32.load offset=4
     (get_local $3)
    )
   )
  )
  (set_local $5
   (i32.add
    (tee_local $3
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $5
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $5)
       (i32.const 1)
      )
     )
    )
    (i32.const 8)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $3)
   )
  )
  (loop $label$2
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (br_if $label$2
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$3
   (block $label$4
    (br_if $label$4
     (i32.lt_u
      (get_local $5)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $5)
     )
    )
    (br $label$3)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $5)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $5)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (get_local $5)
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $7)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $8)
   (i32.add
    (get_local $7)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
    (get_local $8)
    (get_local $4)
   )
  )
  (i32.store offset=24
   (get_local $1)
   (call $db_store_i64
    (i64.load offset=8
     (get_local $2)
    )
    (i64.const -4752039648192102400)
    (i64.load
     (i32.load offset=8
      (get_local $0)
     )
    )
    (tee_local $6
     (i64.load
      (get_local $1)
     )
    )
    (get_local $7)
    (get_local $5)
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.lt_u
     (get_local $5)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$6
   (br_if $label$6
    (i64.lt_u
     (get_local $6)
     (i64.load offset=16
      (get_local $2)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $2)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $6)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $6)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZNK5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE31load_object_by_primary_iteratorEl (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $8
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $9)
  )
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $7
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 28)
       )
      )
     )
     (tee_local $2
      (i32.load offset=24
       (get_local $0)
      )
     )
    )
   )
   (set_local $3
    (i32.sub
     (i32.const 0)
     (get_local $2)
    )
   )
   (set_local $6
    (i32.add
     (get_local $7)
     (i32.const -24)
    )
   )
   (loop $label$1
    (br_if $label$0
     (i32.eq
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
    (set_local $7
     (get_local $6)
    )
    (set_local $6
     (tee_local $4
      (i32.add
       (get_local $6)
       (i32.const -24)
      )
     )
    )
    (br_if $label$1
     (i32.ne
      (i32.add
       (get_local $4)
       (get_local $3)
      )
      (i32.const -24)
     )
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.eq
      (get_local $7)
      (get_local $2)
     )
    )
    (set_local $6
     (i32.load
      (i32.add
       (get_local $7)
       (i32.const -24)
      )
     )
    )
    (br $label$2)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $6
       (call $db_get_i64
        (get_local $1)
        (i32.const 0)
        (i32.const 0)
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 528)
   )
   (block $label$4
    (block $label$5
     (br_if $label$5
      (i32.lt_u
       (get_local $6)
       (i32.const 513)
      )
     )
     (set_local $4
      (call $malloc
       (get_local $6)
      )
     )
     (br $label$4)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $4
      (i32.sub
       (get_local $9)
       (i32.and
        (i32.add
         (get_local $6)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $db_get_i64
     (get_local $1)
     (get_local $4)
     (get_local $6)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=32
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=40
    (get_local $8)
    (tee_local $7
     (i32.add
      (get_local $4)
      (get_local $6)
     )
    )
   )
   (block $label$6
    (br_if $label$6
     (i32.le_u
      (get_local $6)
      (i32.const 512)
     )
    )
    (call $free
     (get_local $4)
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $8)
       (i32.const 40)
      )
     )
    )
    (set_local $4
     (i32.load offset=36
      (get_local $8)
     )
    )
   )
   (i32.store offset=16
    (tee_local $6
     (call $_Znwj
      (i32.const 32)
     )
    )
    (i32.const 0)
   )
   (i64.store offset=8 align=4
    (get_local $6)
    (i64.const 0)
   )
   (i32.store offset=20
    (get_local $6)
    (get_local $0)
   )
   (call $eosio_assert
    (i32.gt_u
     (i32.sub
      (get_local $7)
      (get_local $4)
     )
     (i32.const 7)
    )
    (i32.const 128)
   )
   (drop
    (call $memcpy
     (get_local $6)
     (get_local $4)
     (i32.const 8)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (i32.add
     (get_local $4)
     (i32.const 8)
    )
   )
   (drop
    (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
     (i32.add
      (get_local $8)
      (i32.const 32)
     )
     (i32.add
      (get_local $6)
      (i32.const 8)
     )
    )
   )
   (i32.store offset=24
    (get_local $6)
    (get_local $1)
   )
   (i32.store offset=24
    (get_local $8)
    (get_local $6)
   )
   (i64.store offset=16
    (get_local $8)
    (tee_local $5
     (i64.load
      (get_local $6)
     )
    )
   )
   (i32.store offset=12
    (get_local $8)
    (tee_local $7
     (i32.load offset=24
      (get_local $6)
     )
    )
   )
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.ge_u
       (tee_local $4
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 32)
        )
       )
      )
     )
     (i64.store offset=8
      (get_local $4)
      (get_local $5)
     )
     (i32.store offset=16
      (get_local $4)
      (get_local $7)
     )
     (i32.store offset=24
      (get_local $8)
      (i32.const 0)
     )
     (i32.store
      (get_local $4)
      (get_local $6)
     )
     (i32.store
      (get_local $1)
      (i32.add
       (get_local $4)
       (i32.const 24)
      )
     )
     (br $label$7)
    )
    (call $_ZNSt3__16vectorIN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
     (i32.add
      (get_local $0)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 16)
     )
     (i32.add
      (get_local $8)
      (i32.const 12)
     )
    )
   )
   (set_local $4
    (i32.load offset=24
     (get_local $8)
    )
   )
   (i32.store offset=24
    (get_local $8)
    (i32.const 0)
   )
   (br_if $label$2
    (i32.eqz
     (get_local $4)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=8
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 16)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 48)
   )
  )
  (get_local $6)
 )
 (func $_ZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE6modifyIZNS2_9setrsakeyENSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEE4$_14EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (local $7 i64)
  (local $8 i32)
  (local $9 i32)
  (set_local $9
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=20
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (tee_local $5
     (i32.add
      (get_local $1)
      (i32.const 8)
     )
    )
    (i32.load
     (get_local $3)
    )
   )
  )
  (call $eosio_assert
   (i64.eq
    (get_local $4)
    (i64.load
     (get_local $1)
    )
   )
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $6
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 8)
   )
  )
  (set_local $7
   (i64.extend_u/i32
    (get_local $6)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $7
      (i64.shr_u
       (get_local $7)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $8
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $8
     (i32.sub
      (get_local $8)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store
   (get_local $9)
   (get_local $8)
  )
  (i32.store offset=8
   (get_local $9)
   (i32.add
    (get_local $8)
    (get_local $3)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (get_local $3)
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $8)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $9)
   (i32.add
    (get_local $8)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
    (get_local $9)
    (get_local $5)
   )
  )
  (call $db_update_i64
   (i32.load offset=24
    (get_local $1)
   )
   (get_local $2)
   (get_local $8)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $8)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $9)
    (i32.const 16)
   )
  )
 )
 (func $_ZNSt3__16vectorIN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_ (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.ge_u
      (tee_local $5
       (i32.add
        (tee_local $4
         (i32.div_s
          (i32.sub
           (i32.load offset=4
            (get_local $0)
           )
           (tee_local $6
            (i32.load
             (get_local $0)
            )
           )
          )
          (i32.const 24)
         )
        )
        (i32.const 1)
       )
      )
      (i32.const 178956971)
     )
    )
    (set_local $7
     (i32.const 178956970)
    )
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.gt_u
        (tee_local $6
         (i32.div_s
          (i32.sub
           (i32.load offset=8
            (get_local $0)
           )
           (get_local $6)
          )
          (i32.const 24)
         )
        )
        (i32.const 89478484)
       )
      )
      (br_if $label$2
       (i32.eqz
        (tee_local $7
         (select
          (get_local $5)
          (tee_local $7
           (i32.shl
            (get_local $6)
            (i32.const 1)
           )
          )
          (i32.lt_u
           (get_local $7)
           (get_local $5)
          )
         )
        )
       )
      )
     )
     (set_local $6
      (call $_Znwj
       (i32.mul
        (get_local $7)
        (i32.const 24)
       )
      )
     )
     (br $label$0)
    )
    (set_local $7
     (i32.const 0)
    )
    (set_local $6
     (i32.const 0)
    )
    (br $label$0)
   )
   (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
    (get_local $0)
   )
   (unreachable)
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (i32.store
   (get_local $1)
   (i32.const 0)
  )
  (i32.store
   (tee_local $1
    (i32.add
     (get_local $6)
     (i32.mul
      (get_local $4)
      (i32.const 24)
     )
    )
   )
   (get_local $5)
  )
  (i64.store offset=8
   (get_local $1)
   (i64.load
    (get_local $2)
   )
  )
  (i32.store offset=16
   (get_local $1)
   (i32.load
    (get_local $3)
   )
  )
  (set_local $4
   (i32.add
    (get_local $6)
    (i32.mul
     (get_local $7)
     (i32.const 24)
    )
   )
  )
  (set_local $5
   (i32.add
    (get_local $1)
    (i32.const 24)
   )
  )
  (block $label$4
   (block $label$5
    (br_if $label$5
     (i32.eq
      (tee_local $6
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 4)
        )
       )
      )
      (tee_local $7
       (i32.load
        (get_local $0)
       )
      )
     )
    )
    (loop $label$6
     (set_local $3
      (i32.load
       (tee_local $2
        (i32.add
         (get_local $6)
         (i32.const -24)
        )
       )
      )
     )
     (i32.store
      (get_local $2)
      (i32.const 0)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
      (get_local $3)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -8)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -8)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -12)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -12)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -16)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -16)
       )
      )
     )
     (set_local $1
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
     )
     (set_local $6
      (get_local $2)
     )
     (br_if $label$6
      (i32.ne
       (get_local $7)
       (get_local $2)
      )
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $6
     (i32.load
      (get_local $0)
     )
    )
    (br $label$4)
   )
   (set_local $6
    (get_local $7)
   )
  )
  (i32.store
   (get_local $0)
   (get_local $1)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (get_local $5)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
   (get_local $4)
  )
  (block $label$7
   (br_if $label$7
    (i32.eq
     (get_local $7)
     (get_local $6)
    )
   )
   (loop $label$8
    (set_local $1
     (i32.load
      (tee_local $7
       (i32.add
        (get_local $7)
        (i32.const -24)
       )
      )
     )
    )
    (i32.store
     (get_local $7)
     (i32.const 0)
    )
    (block $label$9
     (br_if $label$9
      (i32.eqz
       (get_local $1)
      )
     )
     (block $label$10
      (br_if $label$10
       (i32.eqz
        (i32.and
         (i32.load8_u offset=8
          (get_local $1)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 16)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $1)
     )
    )
    (br_if $label$8
     (i32.ne
      (get_local $6)
      (get_local $7)
     )
    )
   )
  )
  (block $label$11
   (br_if $label$11
    (i32.eqz
     (get_local $6)
    )
   )
   (call $_ZdlPv
    (get_local $6)
   )
  )
 )
 (func $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i64)
  (local $8 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (set_local $7
   (i64.extend_u/i32
    (select
     (i32.load offset=4
      (get_local $1)
     )
     (i32.shr_u
      (tee_local $5
       (i32.load8_u
        (get_local $1)
       )
      )
      (i32.const 1)
     )
     (i32.and
      (get_local $5)
      (i32.const 1)
     )
    )
   )
  )
  (set_local $6
   (i32.load offset=4
    (get_local $0)
   )
  )
  (set_local $4
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
  )
  (set_local $5
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
  )
  (loop $label$0
   (set_local $2
    (i32.wrap/i64
     (get_local $7)
    )
   )
   (i32.store8 offset=15
    (get_local $8)
    (i32.or
     (i32.shl
      (tee_local $3
       (i64.ne
        (tee_local $7
         (i64.shr_u
          (get_local $7)
          (i64.const 7)
         )
        )
        (i64.const 0)
       )
      )
      (i32.const 7)
     )
     (i32.and
      (get_local $2)
      (i32.const 127)
     )
    )
   )
   (call $eosio_assert
    (i32.gt_s
     (i32.sub
      (i32.load
       (get_local $4)
      )
      (get_local $6)
     )
     (i32.const 0)
    )
    (i32.const 512)
   )
   (drop
    (call $memcpy
     (i32.load
      (get_local $5)
     )
     (i32.add
      (get_local $8)
      (i32.const 15)
     )
     (i32.const 1)
    )
   )
   (i32.store
    (get_local $5)
    (tee_local $6
     (i32.add
      (i32.load
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (br_if $label$0
    (get_local $3)
   )
  )
  (block $label$1
   (br_if $label$1
    (i32.eqz
     (tee_local $5
      (select
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 4)
        )
       )
       (i32.shr_u
        (tee_local $5
         (i32.load8_u
          (get_local $1)
         )
        )
        (i32.const 1)
       )
       (tee_local $2
        (i32.and
         (get_local $5)
         (i32.const 1)
        )
       )
      )
     )
    )
   )
   (set_local $3
    (i32.load offset=8
     (get_local $1)
    )
   )
   (call $eosio_assert
    (i32.ge_s
     (i32.sub
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 8)
       )
      )
      (get_local $6)
     )
     (get_local $5)
    )
    (i32.const 512)
   )
   (drop
    (call $memcpy
     (i32.load
      (tee_local $6
       (i32.add
        (get_local $0)
        (i32.const 4)
       )
      )
     )
     (select
      (get_local $3)
      (i32.add
       (get_local $1)
       (i32.const 1)
      )
      (get_local $2)
     )
     (get_local $5)
    )
   )
   (i32.store
    (get_local $6)
    (i32.add
     (i32.load
      (get_local $6)
     )
     (get_local $5)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZN5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE14const_iteratormmEv (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $2
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (tee_local $1
       (i32.load offset=4
        (get_local $0)
       )
      )
     )
    )
    (call $eosio_assert
     (i32.xor
      (i32.shr_u
       (tee_local $1
        (call $db_previous_i64
         (i32.load offset=24
          (get_local $1)
         )
         (i32.add
          (get_local $2)
          (i32.const 8)
         )
        )
       )
       (i32.const 31)
      )
      (i32.const 1)
     )
     (i32.const 688)
    )
    (br $label$0)
   )
   (call $eosio_assert
    (i32.ne
     (tee_local $1
      (call $db_end_i64
       (i64.load
        (tee_local $1
         (i32.load
          (get_local $0)
         )
        )
       )
       (i64.load offset=8
        (get_local $1)
       )
       (i64.const -4752039648192102400)
      )
     )
     (i32.const -1)
    )
    (i32.const 624)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $1
       (call $db_previous_i64
        (get_local $1)
        (i32.add
         (get_local $2)
         (i32.const 8)
        )
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 624)
   )
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (call $_ZNK5eosio11multi_indexILy13694704425517449216EN21UnificationFoundation16unification_uapp9rsapubkeyEJEE31load_object_by_primary_iteratorEl
    (i32.load
     (get_local $0)
    )
    (get_local $1)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $2)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZN5boost4mp116detail16tuple_apply_implIRZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES6_JRKyS8_RKNSt3__112basic_stringIcNS9_11char_traitsIcEENS9_9allocatorIcEEEESH_EEEbPT_MT0_FvDpT1_EEUlDpT_E_RNS9_5tupleIJyySF_SF_EEEJLj0ELj1ELj2ELj3EEEEDTclclsr3stdE7forwardISI_Efp_Espclsr3stdE3getIXT1_EEclsr3stdE7forwardISK_Efp0_EEEEOSI_OSK_NS0_16integer_sequenceIjJXspT1_EEEE (param $0 i32) (param $1 i32)
  (local $2 i64)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $5
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $2
   (i64.load offset=8
    (get_local $1)
   )
  )
  (set_local $3
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
    (i32.add
     (get_local $1)
     (i32.const 16)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (get_local $5)
    (i32.add
     (get_local $1)
     (i32.const 28)
    )
   )
  )
  (i64.store offset=40
   (get_local $5)
   (get_local $3)
  )
  (i64.store offset=32
   (get_local $5)
   (get_local $2)
  )
  (set_local $0
   (i32.add
    (i32.load
     (i32.load
      (get_local $0)
     )
    )
    (i32.shr_s
     (tee_local $4
      (i32.load offset=4
       (tee_local $1
        (i32.load offset=4
         (get_local $0)
        )
       )
      )
     )
     (i32.const 1)
    )
   )
  )
  (set_local $1
   (i32.load
    (get_local $1)
   )
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (i32.and
      (get_local $4)
      (i32.const 1)
     )
    )
   )
   (set_local $1
    (i32.load
     (i32.add
      (i32.load
       (get_local $0)
      )
      (get_local $1)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiiii)
   (get_local $0)
   (i32.add
    (get_local $5)
    (i32.const 40)
   )
   (i32.add
    (get_local $5)
    (i32.const 32)
   )
   (i32.add
    (get_local $5)
    (i32.const 16)
   )
   (get_local $5)
   (get_local $1)
  )
  (block $label$1
   (br_if $label$1
    (i32.eqz
     (i32.and
      (i32.load8_u
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=8
     (get_local $5)
    )
   )
  )
  (block $label$2
   (br_if $label$2
    (i32.eqz
     (i32.and
      (i32.load8_u offset=16
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=24
     (get_local $5)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $5)
    (i32.const 48)
   )
  )
 )
 (func $_ZNK5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE31load_object_by_primary_iteratorEl (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $8
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $9)
  )
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $7
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 28)
       )
      )
     )
     (tee_local $2
      (i32.load offset=24
       (get_local $0)
      )
     )
    )
   )
   (set_local $3
    (i32.sub
     (i32.const 0)
     (get_local $2)
    )
   )
   (set_local $6
    (i32.add
     (get_local $7)
     (i32.const -24)
    )
   )
   (loop $label$1
    (br_if $label$0
     (i32.eq
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
    (set_local $7
     (get_local $6)
    )
    (set_local $6
     (tee_local $4
      (i32.add
       (get_local $6)
       (i32.const -24)
      )
     )
    )
    (br_if $label$1
     (i32.ne
      (i32.add
       (get_local $4)
       (get_local $3)
      )
      (i32.const -24)
     )
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.eq
      (get_local $7)
      (get_local $2)
     )
    )
    (set_local $6
     (i32.load
      (i32.add
       (get_local $7)
       (i32.const -24)
      )
     )
    )
    (br $label$2)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $6
       (call $db_get_i64
        (get_local $1)
        (i32.const 0)
        (i32.const 0)
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 528)
   )
   (block $label$4
    (block $label$5
     (br_if $label$5
      (i32.lt_u
       (get_local $6)
       (i32.const 513)
      )
     )
     (set_local $4
      (call $malloc
       (get_local $6)
      )
     )
     (br $label$4)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $4
      (i32.sub
       (get_local $9)
       (i32.and
        (i32.add
         (get_local $6)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $db_get_i64
     (get_local $1)
     (get_local $4)
     (get_local $6)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=32
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=40
    (get_local $8)
    (i32.add
     (get_local $4)
     (get_local $6)
    )
   )
   (block $label$6
    (br_if $label$6
     (i32.lt_u
      (get_local $6)
      (i32.const 513)
     )
    )
    (call $free
     (get_local $4)
    )
   )
   (i32.store offset=36
    (tee_local $6
     (call $_Znwj
      (i32.const 80)
     )
    )
    (i32.const 0)
   )
   (i64.store offset=28 align=4
    (get_local $6)
    (i64.const 0)
   )
   (i32.store offset=44
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=48
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=52
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=56
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=60
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=64
    (get_local $6)
    (i32.const 0)
   )
   (i32.store offset=68
    (get_local $6)
    (get_local $0)
   )
   (drop
    (call $_ZN21UnificationFoundationrsIN5eosio10datastreamIPKcEEEERT_S7_RNS_16unification_uapp8datareqsE
     (i32.add
      (get_local $8)
      (i32.const 32)
     )
     (get_local $6)
    )
   )
   (i32.store offset=72
    (get_local $6)
    (get_local $1)
   )
   (i32.store offset=24
    (get_local $8)
    (get_local $6)
   )
   (i64.store offset=16
    (get_local $8)
    (tee_local $5
     (i64.load
      (get_local $6)
     )
    )
   )
   (i32.store offset=12
    (get_local $8)
    (tee_local $7
     (i32.load offset=72
      (get_local $6)
     )
    )
   )
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.ge_u
       (tee_local $4
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 32)
        )
       )
      )
     )
     (i64.store offset=8
      (get_local $4)
      (get_local $5)
     )
     (i32.store offset=16
      (get_local $4)
      (get_local $7)
     )
     (i32.store offset=24
      (get_local $8)
      (i32.const 0)
     )
     (i32.store
      (get_local $4)
      (get_local $6)
     )
     (i32.store
      (get_local $1)
      (i32.add
       (get_local $4)
       (i32.const 24)
      )
     )
     (br $label$7)
    )
    (call $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
     (i32.add
      (get_local $0)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 16)
     )
     (i32.add
      (get_local $8)
      (i32.const 12)
     )
    )
   )
   (set_local $4
    (i32.load offset=24
     (get_local $8)
    )
   )
   (i32.store offset=24
    (get_local $8)
    (i32.const 0)
   )
   (br_if $label$2
    (i32.eqz
     (get_local $4)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=56
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 64)
      )
     )
    )
   )
   (block $label$10
    (br_if $label$10
     (i32.eqz
      (i32.and
       (i32.load8_u offset=44
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 52)
      )
     )
    )
   )
   (block $label$11
    (br_if $label$11
     (i32.eqz
      (i32.and
       (i32.load8_u offset=28
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 36)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 48)
   )
  )
  (get_local $6)
 )
 (func $_ZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE6modifyIZNS2_9updatereqERKyS7_RKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEESG_E4$_12EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $6
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=68
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 44)
    )
    (i32.load
     (get_local $3)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 56)
    )
    (i32.load offset=4
     (get_local $3)
    )
   )
  )
  (call $eosio_assert
   (i64.eq
    (get_local $4)
    (i64.load
     (get_local $1)
    )
   )
   (i32.const 448)
  )
  (i32.store
   (tee_local $3
    (get_local $6)
   )
   (i32.const 0)
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIjEEEERT_S5_RKNS_16unification_uapp8datareqsE
    (get_local $3)
    (get_local $1)
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.lt_u
      (tee_local $5
       (i32.load
        (get_local $3)
       )
      )
      (i32.const 513)
     )
    )
    (set_local $6
     (call $malloc
      (get_local $5)
     )
    )
    (br $label$0)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $6
     (i32.sub
      (get_local $6)
      (i32.and
       (i32.add
        (get_local $5)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $3)
   (get_local $6)
  )
  (i32.store
   (get_local $3)
   (get_local $6)
  )
  (i32.store offset=8
   (get_local $3)
   (i32.add
    (get_local $6)
    (get_local $5)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp8datareqsE
    (get_local $3)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=72
    (get_local $1)
   )
   (get_local $2)
   (get_local $6)
   (get_local $5)
  )
  (block $label$2
   (br_if $label$2
    (i32.lt_u
     (get_local $5)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $6)
   )
  )
  (block $label$3
   (br_if $label$3
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $3)
    (i32.const 16)
   )
  )
 )
 (func $_ZNSt3__113__vector_baseIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEED2Ev (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (local $3 i32)
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (tee_local $1
      (i32.load
       (get_local $0)
      )
     )
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.eq
       (tee_local $3
        (i32.load offset=4
         (get_local $0)
        )
       )
       (get_local $1)
      )
     )
     (loop $label$3
      (set_local $2
       (i32.load
        (tee_local $3
         (i32.add
          (get_local $3)
          (i32.const -24)
         )
        )
       )
      )
      (i32.store
       (get_local $3)
       (i32.const 0)
      )
      (block $label$4
       (br_if $label$4
        (i32.eqz
         (get_local $2)
        )
       )
       (block $label$5
        (br_if $label$5
         (i32.eqz
          (i32.and
           (i32.load8_u offset=56
            (get_local $2)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $2)
           (i32.const 64)
          )
         )
        )
       )
       (block $label$6
        (br_if $label$6
         (i32.eqz
          (i32.and
           (i32.load8_u offset=44
            (get_local $2)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $2)
           (i32.const 52)
          )
         )
        )
       )
       (block $label$7
        (br_if $label$7
         (i32.eqz
          (i32.and
           (i32.load8_u offset=28
            (get_local $2)
           )
           (i32.const 1)
          )
         )
        )
        (call $_ZdlPv
         (i32.load
          (i32.add
           (get_local $2)
           (i32.const 36)
          )
         )
        )
       )
       (call $_ZdlPv
        (get_local $2)
       )
      )
      (br_if $label$3
       (i32.ne
        (get_local $1)
        (get_local $3)
       )
      )
     )
     (set_local $2
      (i32.load
       (get_local $0)
      )
     )
     (br $label$1)
    )
    (set_local $2
     (get_local $1)
    )
   )
   (i32.store
    (i32.add
     (get_local $0)
     (i32.const 4)
    )
    (get_local $1)
   )
   (call $_ZdlPv
    (get_local $2)
   )
  )
  (get_local $0)
 )
 (func $_ZN21UnificationFoundationlsIN5eosio10datastreamIjEEEERT_S5_RKNS_16unification_uapp8datareqsE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i64)
  (local $4 i32)
  (i32.store
   (get_local $0)
   (tee_local $4
    (i32.add
     (i32.load
      (get_local $0)
     )
     (i32.const 25)
    )
   )
  )
  (set_local $3
   (i64.extend_u/i32
    (select
     (i32.load
      (i32.add
       (get_local $1)
       (i32.const 32)
      )
     )
     (i32.shr_u
      (tee_local $2
       (i32.load8_u offset=28
        (get_local $1)
       )
      )
      (i32.const 1)
     )
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
  )
  (loop $label$0
   (set_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $3
      (i64.shr_u
       (get_local $3)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (i32.store
   (get_local $0)
   (get_local $4)
  )
  (block $label$1
   (br_if $label$1
    (i32.eqz
     (tee_local $2
      (select
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 32)
        )
       )
       (i32.shr_u
        (tee_local $2
         (i32.load8_u
          (i32.add
           (get_local $1)
           (i32.const 28)
          )
         )
        )
        (i32.const 1)
       )
       (i32.and
        (get_local $2)
        (i32.const 1)
       )
      )
     )
    )
   )
   (i32.store
    (get_local $0)
    (tee_local $4
     (i32.add
      (get_local $2)
      (get_local $4)
     )
    )
   )
  )
  (i32.store
   (get_local $0)
   (tee_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
  )
  (set_local $3
   (i64.extend_u/i32
    (select
     (i32.load
      (i32.add
       (get_local $1)
       (i32.const 48)
      )
     )
     (i32.shr_u
      (tee_local $2
       (i32.load8_u offset=44
        (get_local $1)
       )
      )
      (i32.const 1)
     )
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
  )
  (loop $label$2
   (set_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
   (br_if $label$2
    (i64.ne
     (tee_local $3
      (i64.shr_u
       (get_local $3)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (i32.store
   (get_local $0)
   (get_local $4)
  )
  (block $label$3
   (br_if $label$3
    (i32.eqz
     (tee_local $2
      (select
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 48)
        )
       )
       (i32.shr_u
        (tee_local $2
         (i32.load8_u
          (i32.add
           (get_local $1)
           (i32.const 44)
          )
         )
        )
        (i32.const 1)
       )
       (i32.and
        (get_local $2)
        (i32.const 1)
       )
      )
     )
    )
   )
   (i32.store
    (get_local $0)
    (tee_local $4
     (i32.add
      (get_local $2)
      (get_local $4)
     )
    )
   )
  )
  (set_local $3
   (i64.extend_u/i32
    (select
     (i32.load
      (i32.add
       (get_local $1)
       (i32.const 60)
      )
     )
     (i32.shr_u
      (tee_local $2
       (i32.load8_u offset=56
        (get_local $1)
       )
      )
      (i32.const 1)
     )
     (i32.and
      (get_local $2)
      (i32.const 1)
     )
    )
   )
  )
  (loop $label$4
   (set_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
   (br_if $label$4
    (i64.ne
     (tee_local $3
      (i64.shr_u
       (get_local $3)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (i32.store
   (get_local $0)
   (get_local $4)
  )
  (block $label$5
   (br_if $label$5
    (i32.eqz
     (tee_local $1
      (select
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 60)
        )
       )
       (i32.shr_u
        (tee_local $1
         (i32.load8_u
          (i32.add
           (get_local $1)
           (i32.const 56)
          )
         )
        )
        (i32.const 1)
       )
       (i32.and
        (get_local $1)
        (i32.const 1)
       )
      )
     )
    )
   )
   (i32.store
    (get_local $0)
    (i32.add
     (get_local $1)
     (get_local $4)
    )
   )
  )
  (get_local $0)
 )
 (func $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp8datareqsE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 16)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 24)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (tee_local $0
       (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
        (get_local $0)
        (i32.add
         (get_local $1)
         (i32.const 28)
        )
       )
      )
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 40)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
    (get_local $0)
    (i32.add
     (get_local $1)
     (i32.const 44)
    )
   )
   (i32.add
    (get_local $1)
    (i32.const 56)
   )
  )
 )
 (func $_ZN21UnificationFoundationrsIN5eosio10datastreamIPKcEEEERT_S7_RNS_16unification_uapp8datareqsE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $1)
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 16)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (get_local $0)
    )
    (get_local $2)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 24)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
       (get_local $0)
       (i32.add
        (get_local $1)
        (i32.const 28)
       )
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 40)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (get_local $0)
    (i32.add
     (get_local $1)
     (i32.const 44)
    )
   )
   (i32.add
    (get_local $1)
    (i32.const 56)
   )
  )
 )
 (func $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_ (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (local $10 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $10
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 32)
    )
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.ge_u
      (tee_local $8
       (i32.add
        (tee_local $4
         (i32.div_s
          (i32.sub
           (i32.load offset=4
            (get_local $0)
           )
           (tee_local $9
            (i32.load
             (get_local $0)
            )
           )
          )
          (i32.const 24)
         )
        )
        (i32.const 1)
       )
      )
      (i32.const 178956971)
     )
    )
    (set_local $5
     (i32.add
      (get_local $0)
      (i32.const 8)
     )
    )
    (block $label$2
     (block $label$3
      (block $label$4
       (br_if $label$4
        (i32.ge_u
         (tee_local $9
          (i32.div_s
           (i32.sub
            (i32.load offset=8
             (get_local $0)
            )
            (get_local $9)
           )
           (i32.const 24)
          )
         )
         (i32.const 89478485)
        )
       )
       (i32.store
        (i32.add
         (get_local $10)
         (i32.const 24)
        )
        (get_local $5)
       )
       (set_local $5
        (i32.const 0)
       )
       (i32.store offset=20
        (get_local $10)
        (i32.const 0)
       )
       (set_local $7
        (i32.add
         (get_local $10)
         (i32.const 20)
        )
       )
       (br_if $label$2
        (i32.eqz
         (tee_local $9
          (select
           (get_local $8)
           (tee_local $9
            (i32.shl
             (get_local $9)
             (i32.const 1)
            )
           )
           (i32.lt_u
            (get_local $9)
            (get_local $8)
           )
          )
         )
        )
       )
       (set_local $5
        (get_local $9)
       )
       (br $label$3)
      )
      (i32.store
       (i32.add
        (get_local $10)
        (i32.const 24)
       )
       (get_local $5)
      )
      (i32.store offset=20
       (get_local $10)
       (i32.const 0)
      )
      (set_local $7
       (i32.add
        (get_local $10)
        (i32.const 20)
       )
      )
      (set_local $5
       (i32.const 178956970)
      )
     )
     (set_local $8
      (call $_Znwj
       (i32.mul
        (get_local $5)
        (i32.const 24)
       )
      )
     )
     (br $label$0)
    )
    (set_local $8
     (i32.const 0)
    )
    (br $label$0)
   )
   (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
    (get_local $0)
   )
   (unreachable)
  )
  (i32.store offset=8
   (get_local $10)
   (get_local $8)
  )
  (i32.store offset=12
   (get_local $10)
   (tee_local $9
    (i32.add
     (get_local $8)
     (i32.mul
      (get_local $4)
      (i32.const 24)
     )
    )
   )
  )
  (i32.store
   (get_local $7)
   (tee_local $5
    (i32.add
     (get_local $8)
     (i32.mul
      (get_local $5)
      (i32.const 24)
     )
    )
   )
  )
  (set_local $8
   (i32.load
    (get_local $1)
   )
  )
  (i32.store
   (get_local $1)
   (i32.const 0)
  )
  (set_local $1
   (i32.load
    (get_local $3)
   )
  )
  (set_local $6
   (i64.load
    (get_local $2)
   )
  )
  (i32.store
   (get_local $9)
   (get_local $8)
  )
  (i64.store offset=8
   (get_local $9)
   (get_local $6)
  )
  (i32.store offset=16
   (get_local $9)
   (get_local $1)
  )
  (i32.store offset=16
   (get_local $10)
   (tee_local $1
    (i32.add
     (get_local $9)
     (i32.const 24)
    )
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.eq
     (tee_local $8
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 4)
       )
      )
     )
     (tee_local $2
      (i32.load
       (get_local $0)
      )
     )
    )
   )
   (loop $label$6
    (set_local $1
     (i32.load
      (tee_local $5
       (i32.add
        (get_local $8)
        (i32.const -24)
       )
      )
     )
    )
    (i32.store
     (get_local $5)
     (i32.const 0)
    )
    (i32.store
     (i32.add
      (get_local $9)
      (i32.const -24)
     )
     (get_local $1)
    )
    (i32.store
     (i32.add
      (get_local $9)
      (i32.const -8)
     )
     (i32.load
      (i32.add
       (get_local $8)
       (i32.const -8)
      )
     )
    )
    (i32.store
     (i32.add
      (get_local $9)
      (i32.const -12)
     )
     (i32.load
      (i32.add
       (get_local $8)
       (i32.const -12)
      )
     )
    )
    (i32.store
     (i32.add
      (get_local $9)
      (i32.const -16)
     )
     (i32.load
      (i32.add
       (get_local $8)
       (i32.const -16)
      )
     )
    )
    (i32.store offset=12
     (get_local $10)
     (tee_local $9
      (i32.add
       (i32.load offset=12
        (get_local $10)
       )
       (i32.const -24)
      )
     )
    )
    (set_local $8
     (get_local $5)
    )
    (br_if $label$6
     (i32.ne
      (get_local $2)
      (get_local $5)
     )
    )
   )
   (set_local $8
    (i32.load
     (i32.add
      (get_local $0)
      (i32.const 4)
     )
    )
   )
   (set_local $5
    (i32.load
     (get_local $7)
    )
   )
   (set_local $2
    (i32.load
     (get_local $0)
    )
   )
   (set_local $1
    (i32.load
     (i32.add
      (get_local $10)
      (i32.const 16)
     )
    )
   )
  )
  (i32.store
   (get_local $0)
   (get_local $9)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (get_local $1)
  )
  (i32.store
   (i32.add
    (i32.add
     (get_local $10)
     (i32.const 8)
    )
    (i32.const 8)
   )
   (get_local $8)
  )
  (set_local $8
   (i32.load
    (tee_local $9
     (i32.add
      (get_local $0)
      (i32.const 8)
     )
    )
   )
  )
  (i32.store
   (get_local $9)
   (get_local $5)
  )
  (i32.store offset=12
   (get_local $10)
   (get_local $2)
  )
  (i32.store
   (get_local $7)
   (get_local $8)
  )
  (i32.store offset=8
   (get_local $10)
   (get_local $2)
  )
  (drop
   (call $_ZNSt3__114__split_bufferIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrERNS_9allocatorIS7_EEED2Ev
    (i32.add
     (get_local $10)
     (i32.const 8)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $10)
    (i32.const 32)
   )
  )
 )
 (func $_ZNSt3__114__split_bufferIN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE8item_ptrERNS_9allocatorIS7_EEED2Ev (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $2
      (i32.load offset=8
       (get_local $0)
      )
     )
     (tee_local $1
      (i32.load offset=4
       (get_local $0)
      )
     )
    )
   )
   (set_local $4
    (i32.add
     (get_local $0)
     (i32.const 8)
    )
   )
   (loop $label$1
    (i32.store
     (get_local $4)
     (tee_local $3
      (i32.add
       (get_local $2)
       (i32.const -24)
      )
     )
    )
    (set_local $2
     (i32.load
      (get_local $3)
     )
    )
    (i32.store
     (get_local $3)
     (i32.const 0)
    )
    (block $label$2
     (br_if $label$2
      (i32.eqz
       (get_local $2)
      )
     )
     (block $label$3
      (br_if $label$3
       (i32.eqz
        (i32.and
         (i32.load8_u offset=56
          (get_local $2)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $2)
         (i32.const 64)
        )
       )
      )
     )
     (block $label$4
      (br_if $label$4
       (i32.eqz
        (i32.and
         (i32.load8_u offset=44
          (get_local $2)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $2)
         (i32.const 52)
        )
       )
      )
     )
     (block $label$5
      (br_if $label$5
       (i32.eqz
        (i32.and
         (i32.load8_u offset=28
          (get_local $2)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $2)
         (i32.const 36)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $2)
     )
    )
    (br_if $label$1
     (i32.ne
      (tee_local $2
       (i32.load
        (get_local $4)
       )
      )
      (get_local $1)
     )
    )
   )
  )
  (block $label$6
   (br_if $label$6
    (i32.eqz
     (tee_local $2
      (i32.load
       (get_local $0)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $2)
   )
  )
  (get_local $0)
 )
 (func $_ZN5boost6fusion6detail17for_each_unrolledILi5EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJyyhNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJyyhSD_hEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (set_local $3
   (i32.load
    (get_local $0)
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (tee_local $2
       (i32.load
        (get_local $1)
       )
      )
     )
     (i32.load offset=4
      (get_local $2)
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $3)
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $2)
   (i32.add
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 8)
   )
  )
  (set_local $2
   (i32.load
    (get_local $0)
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (tee_local $0
       (i32.load
        (get_local $1)
       )
      )
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 8)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 16)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.load
     (get_local $1)
    )
    (i32.add
     (get_local $2)
     (i32.const 20)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $1
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $1)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 32)
    )
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $1)
   (i32.add
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
 )
 (func $_ZZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE7emplaceIZNS2_7initreqERKyS7_RKhRKNSt3__112basic_stringIcNSA_11char_traitsIcEENSA_9allocatorIcEEEES9_E4$_11EENS4_14const_iteratorEyOT_ENKUlRSL_E_clINS4_4itemEEEDaSN_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $7
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (set_local $2
   (i32.load
    (get_local $0)
   )
  )
  (block $label$0
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.load offset=16
       (tee_local $5
        (i32.load
         (tee_local $3
          (i32.load offset=4
           (get_local $0)
          )
         )
        )
       )
      )
     )
     (i64.const -1)
    )
   )
   (set_local $6
    (i64.const 0)
   )
   (block $label$1
    (br_if $label$1
     (i32.lt_s
      (tee_local $4
       (call $db_lowerbound_i64
        (i64.load
         (get_local $5)
        )
        (i64.load offset=8
         (get_local $5)
        )
        (i64.const 5310425292135727104)
        (i64.const 0)
       )
      )
      (i32.const 0)
     )
    )
    (drop
     (call $_ZNK5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE31load_object_by_primary_iteratorEl
      (get_local $5)
      (get_local $4)
     )
    )
    (i32.store offset=4
     (get_local $7)
     (i32.const 0)
    )
    (i32.store
     (get_local $7)
     (get_local $5)
    )
    (set_local $6
     (select
      (i64.const -2)
      (i64.add
       (tee_local $6
        (i64.load
         (i32.load offset=4
          (call $_ZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE14const_iteratormmEv
           (get_local $7)
          )
         )
        )
       )
       (i64.const 1)
      )
      (i64.gt_u
       (get_local $6)
       (i64.const -3)
      )
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
    (get_local $6)
   )
  )
  (call $eosio_assert
   (i64.lt_u
    (get_local $6)
    (i64.const -2)
   )
   (i32.const 560)
  )
  (i64.store
   (get_local $1)
   (i64.load
    (i32.add
     (get_local $5)
     (i32.const 16)
    )
   )
  )
  (i64.store offset=8
   (get_local $1)
   (i64.load
    (i32.load offset=4
     (get_local $3)
    )
   )
  )
  (i64.store offset=16
   (get_local $1)
   (i64.load
    (i32.load offset=8
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=24
   (get_local $1)
   (i32.load8_u
    (i32.load offset=12
     (get_local $3)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 28)
    )
    (i32.load offset=16
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=40
   (get_local $1)
   (i32.load8_u
    (i32.load offset=20
     (get_local $3)
    )
   )
  )
  (i32.store
   (get_local $7)
   (i32.const 0)
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIjEEEERT_S5_RKNS_16unification_uapp8datareqsE
    (get_local $7)
    (get_local $1)
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.lt_u
      (tee_local $5
       (i32.load
        (get_local $7)
       )
      )
      (i32.const 513)
     )
    )
    (set_local $3
     (call $malloc
      (get_local $5)
     )
    )
    (br $label$2)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $3
     (i32.sub
      (get_local $8)
      (i32.and
       (i32.add
        (get_local $5)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $7)
   (get_local $3)
  )
  (i32.store
   (get_local $7)
   (get_local $3)
  )
  (i32.store offset=8
   (get_local $7)
   (i32.add
    (get_local $3)
    (get_local $5)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp8datareqsE
    (get_local $7)
    (get_local $1)
   )
  )
  (i32.store offset=72
   (get_local $1)
   (call $db_store_i64
    (i64.load offset=8
     (get_local $2)
    )
    (i64.const 5310425292135727104)
    (i64.load
     (i32.load offset=8
      (get_local $0)
     )
    )
    (tee_local $6
     (i64.load
      (get_local $1)
     )
    )
    (get_local $3)
    (get_local $5)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $5)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $3)
   )
  )
  (block $label$5
   (br_if $label$5
    (i64.lt_u
     (get_local $6)
     (i64.load offset=16
      (get_local $2)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $2)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $6)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $6)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosio4packINS_6actionEEENSt3__16vectorIcNS2_9allocatorIcEEEERKT_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=8
   (get_local $0)
   (i32.const 0)
  )
  (i64.store align=4
   (get_local $0)
   (i64.const 0)
  )
  (set_local $5
   (i32.const 16)
  )
  (set_local $2
   (i32.add
    (get_local $1)
    (i32.const 16)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (i32.shr_s
     (tee_local $4
      (i32.sub
       (tee_local $7
        (i32.load
         (i32.add
          (get_local $1)
          (i32.const 20)
         )
        )
       )
       (tee_local $3
        (i32.load offset=16
         (get_local $1)
        )
       )
      )
     )
     (i32.const 4)
    )
   )
  )
  (loop $label$0
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (br_if $label$1
    (i32.eq
     (get_local $3)
     (get_local $7)
    )
   )
   (set_local $5
    (i32.add
     (i32.and
      (get_local $4)
      (i32.const -16)
     )
     (get_local $5)
    )
   )
  )
  (set_local $5
   (i32.sub
    (i32.sub
     (tee_local $7
      (i32.load offset=28
       (get_local $1)
      )
     )
     (get_local $5)
    )
    (tee_local $3
     (i32.load
      (i32.add
       (get_local $1)
       (i32.const 32)
      )
     )
    )
   )
  )
  (set_local $4
   (i32.add
    (get_local $1)
    (i32.const 28)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (i32.sub
     (get_local $3)
     (get_local $7)
    )
   )
  )
  (loop $label$2
   (set_local $5
    (i32.add
     (get_local $5)
     (i32.const -1)
    )
   )
   (br_if $label$2
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (set_local $7
   (i32.const 0)
  )
  (block $label$3
   (block $label$4
    (br_if $label$4
     (i32.eqz
      (get_local $5)
     )
    )
    (call $_ZNSt3__16vectorIcNS_9allocatorIcEEE8__appendEj
     (get_local $0)
     (i32.sub
      (i32.const 0)
      (get_local $5)
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $5
     (i32.load
      (get_local $0)
     )
    )
    (br $label$3)
   )
   (set_local $5
    (i32.const 0)
   )
  )
  (i32.store
   (get_local $8)
   (get_local $5)
  )
  (i32.store offset=8
   (get_local $8)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (get_local $7)
     (get_local $5)
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $5)
    (get_local $1)
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (get_local $7)
     (tee_local $0
      (i32.add
       (get_local $5)
       (i32.const 8)
      )
     )
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $0)
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $8)
   (i32.add
    (get_local $5)
    (i32.const 16)
   )
  )
  (drop
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__16vectorIcNS6_9allocatorIcEEEE
    (call $_ZN5eosiolsINS_10datastreamIPcEENS_16permission_levelEEERT_S6_RKNSt3__16vectorIT0_NS7_9allocatorIS9_EEEE
     (get_local $8)
     (get_local $2)
    )
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosiolsINS_10datastreamIPcEENS_16permission_levelEEERT_S6_RKNSt3__16vectorIT0_NS7_9allocatorIS9_EEEE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (set_local $4
   (i64.extend_u/i32
    (i32.shr_s
     (i32.sub
      (i32.load offset=4
       (get_local $1)
      )
      (i32.load
       (get_local $1)
      )
     )
     (i32.const 4)
    )
   )
  )
  (set_local $5
   (i32.load offset=4
    (get_local $0)
   )
  )
  (set_local $2
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.wrap/i64
     (get_local $4)
    )
   )
   (i32.store8 offset=15
    (get_local $7)
    (i32.or
     (i32.shl
      (tee_local $6
       (i64.ne
        (tee_local $4
         (i64.shr_u
          (get_local $4)
          (i64.const 7)
         )
        )
        (i64.const 0)
       )
      )
      (i32.const 7)
     )
     (i32.and
      (get_local $3)
      (i32.const 127)
     )
    )
   )
   (call $eosio_assert
    (i32.gt_s
     (i32.sub
      (i32.load
       (get_local $2)
      )
      (get_local $5)
     )
     (i32.const 0)
    )
    (i32.const 512)
   )
   (drop
    (call $memcpy
     (i32.load
      (tee_local $3
       (i32.add
        (get_local $0)
        (i32.const 4)
       )
      )
     )
     (i32.add
      (get_local $7)
      (i32.const 15)
     )
     (i32.const 1)
    )
   )
   (i32.store
    (get_local $3)
    (tee_local $5
     (i32.add
      (i32.load
       (get_local $3)
      )
      (i32.const 1)
     )
    )
   )
   (br_if $label$0
    (get_local $6)
   )
  )
  (block $label$1
   (br_if $label$1
    (i32.eq
     (tee_local $6
      (i32.load
       (get_local $1)
      )
     )
     (tee_local $1
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 4)
       )
      )
     )
    )
   )
   (set_local $3
    (i32.add
     (get_local $0)
     (i32.const 4)
    )
   )
   (loop $label$2
    (call $eosio_assert
     (i32.gt_s
      (i32.sub
       (i32.load
        (tee_local $2
         (i32.add
          (get_local $0)
          (i32.const 8)
         )
        )
       )
       (get_local $5)
      )
      (i32.const 7)
     )
     (i32.const 512)
    )
    (drop
     (call $memcpy
      (i32.load
       (get_local $3)
      )
      (get_local $6)
      (i32.const 8)
     )
    )
    (i32.store
     (get_local $3)
     (tee_local $5
      (i32.add
       (i32.load
        (get_local $3)
       )
       (i32.const 8)
      )
     )
    )
    (call $eosio_assert
     (i32.gt_s
      (i32.sub
       (i32.load
        (get_local $2)
       )
       (get_local $5)
      )
      (i32.const 7)
     )
     (i32.const 512)
    )
    (drop
     (call $memcpy
      (i32.load
       (get_local $3)
      )
      (i32.add
       (get_local $6)
       (i32.const 8)
      )
      (i32.const 8)
     )
    )
    (i32.store
     (get_local $3)
     (tee_local $5
      (i32.add
       (i32.load
        (get_local $3)
       )
       (i32.const 8)
      )
     )
    )
    (br_if $label$2
     (i32.ne
      (tee_local $6
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__16vectorIcNS6_9allocatorIcEEEE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i64)
  (local $8 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (set_local $7
   (i64.extend_u/i32
    (i32.sub
     (i32.load offset=4
      (get_local $1)
     )
     (i32.load
      (get_local $1)
     )
    )
   )
  )
  (set_local $6
   (i32.load offset=4
    (get_local $0)
   )
  )
  (set_local $4
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
  )
  (set_local $5
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
  )
  (loop $label$0
   (set_local $2
    (i32.wrap/i64
     (get_local $7)
    )
   )
   (i32.store8 offset=15
    (get_local $8)
    (i32.or
     (i32.shl
      (tee_local $3
       (i64.ne
        (tee_local $7
         (i64.shr_u
          (get_local $7)
          (i64.const 7)
         )
        )
        (i64.const 0)
       )
      )
      (i32.const 7)
     )
     (i32.and
      (get_local $2)
      (i32.const 127)
     )
    )
   )
   (call $eosio_assert
    (i32.gt_s
     (i32.sub
      (i32.load
       (get_local $4)
      )
      (get_local $6)
     )
     (i32.const 0)
    )
    (i32.const 512)
   )
   (drop
    (call $memcpy
     (i32.load
      (get_local $5)
     )
     (i32.add
      (get_local $8)
      (i32.const 15)
     )
     (i32.const 1)
    )
   )
   (i32.store
    (get_local $5)
    (tee_local $6
     (i32.add
      (i32.load
       (get_local $5)
      )
      (i32.const 1)
     )
    )
   )
   (br_if $label$0
    (get_local $3)
   )
  )
  (call $eosio_assert
   (i32.ge_s
    (i32.sub
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 8)
      )
     )
     (get_local $6)
    )
    (tee_local $5
     (i32.sub
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 4)
       )
      )
      (tee_local $2
       (i32.load
        (get_local $1)
       )
      )
     )
    )
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load
     (tee_local $6
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (get_local $2)
    (get_local $5)
   )
  )
  (i32.store
   (get_local $6)
   (i32.add
    (i32.load
     (get_local $6)
    )
    (get_local $5)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZN5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE14const_iteratormmEv (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $2
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (tee_local $1
       (i32.load offset=4
        (get_local $0)
       )
      )
     )
    )
    (call $eosio_assert
     (i32.xor
      (i32.shr_u
       (tee_local $1
        (call $db_previous_i64
         (i32.load offset=72
          (get_local $1)
         )
         (i32.add
          (get_local $2)
          (i32.const 8)
         )
        )
       )
       (i32.const 31)
      )
      (i32.const 1)
     )
     (i32.const 688)
    )
    (br $label$0)
   )
   (call $eosio_assert
    (i32.ne
     (tee_local $1
      (call $db_end_i64
       (i64.load
        (tee_local $1
         (i32.load
          (get_local $0)
         )
        )
       )
       (i64.load offset=8
        (get_local $1)
       )
       (i64.const 5310425292135727104)
      )
     )
     (i32.const -1)
    )
    (i32.const 624)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $1
       (call $db_previous_i64
        (get_local $1)
        (i32.add
         (get_local $2)
         (i32.const 8)
        )
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 624)
   )
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (call $_ZNK5eosio11multi_indexILy5310425292135727104EN21UnificationFoundation16unification_uapp8datareqsEJEE31load_object_by_primary_iteratorEl
    (i32.load
     (get_local $0)
    )
    (get_local $1)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $2)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $8
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $9)
  )
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $7
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 28)
       )
      )
     )
     (tee_local $2
      (i32.load offset=24
       (get_local $0)
      )
     )
    )
   )
   (set_local $3
    (i32.sub
     (i32.const 0)
     (get_local $2)
    )
   )
   (set_local $6
    (i32.add
     (get_local $7)
     (i32.const -24)
    )
   )
   (loop $label$1
    (br_if $label$0
     (i32.eq
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
    (set_local $7
     (get_local $6)
    )
    (set_local $6
     (tee_local $4
      (i32.add
       (get_local $6)
       (i32.const -24)
      )
     )
    )
    (br_if $label$1
     (i32.ne
      (i32.add
       (get_local $4)
       (get_local $3)
      )
      (i32.const -24)
     )
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.eq
      (get_local $7)
      (get_local $2)
     )
    )
    (set_local $6
     (i32.load
      (i32.add
       (get_local $7)
       (i32.const -24)
      )
     )
    )
    (br $label$2)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $6
       (call $db_get_i64
        (get_local $1)
        (i32.const 0)
        (i32.const 0)
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 528)
   )
   (block $label$4
    (block $label$5
     (br_if $label$5
      (i32.lt_u
       (get_local $6)
       (i32.const 513)
      )
     )
     (set_local $4
      (call $malloc
       (get_local $6)
      )
     )
     (br $label$4)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $4
      (i32.sub
       (get_local $9)
       (i32.and
        (i32.add
         (get_local $6)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $db_get_i64
     (get_local $1)
     (get_local $4)
     (get_local $6)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=32
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=40
    (get_local $8)
    (i32.add
     (get_local $4)
     (get_local $6)
    )
   )
   (block $label$6
    (br_if $label$6
     (i32.lt_u
      (get_local $6)
      (i32.const 513)
     )
    )
    (call $free
     (get_local $4)
    )
   )
   (i32.store offset=16
    (tee_local $6
     (call $_Znwj
      (i32.const 40)
     )
    )
    (i32.const 0)
   )
   (i64.store offset=8 align=4
    (get_local $6)
    (i64.const 0)
   )
   (i32.store offset=24
    (get_local $6)
    (get_local $0)
   )
   (drop
    (call $_ZN21UnificationFoundationrsIN5eosio10datastreamIPKcEEEERT_S7_RNS_16unification_uapp11dataschemasE
     (i32.add
      (get_local $8)
      (i32.const 32)
     )
     (get_local $6)
    )
   )
   (i32.store offset=28
    (get_local $6)
    (get_local $1)
   )
   (i32.store offset=24
    (get_local $8)
    (get_local $6)
   )
   (i64.store offset=16
    (get_local $8)
    (tee_local $5
     (i64.load
      (get_local $6)
     )
    )
   )
   (i32.store offset=12
    (get_local $8)
    (tee_local $7
     (i32.load offset=28
      (get_local $6)
     )
    )
   )
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.ge_u
       (tee_local $4
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 32)
        )
       )
      )
     )
     (i64.store offset=8
      (get_local $4)
      (get_local $5)
     )
     (i32.store offset=16
      (get_local $4)
      (get_local $7)
     )
     (i32.store offset=24
      (get_local $8)
      (i32.const 0)
     )
     (i32.store
      (get_local $4)
      (get_local $6)
     )
     (i32.store
      (get_local $1)
      (i32.add
       (get_local $4)
       (i32.const 24)
      )
     )
     (br $label$7)
    )
    (call $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
     (i32.add
      (get_local $0)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 16)
     )
     (i32.add
      (get_local $8)
      (i32.const 12)
     )
    )
   )
   (set_local $4
    (i32.load offset=24
     (get_local $8)
    )
   )
   (i32.store offset=24
    (get_local $8)
    (i32.const 0)
   )
   (br_if $label$2
    (i32.eqz
     (get_local $4)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=8
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 16)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 48)
   )
  )
  (get_local $6)
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_9setschemaERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEEE4$_10EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.load
     (get_local $3)
    )
   )
  )
  (call $eosio_assert
   (i64.eq
    (get_local $4)
    (i64.load
     (get_local $1)
    )
   )
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (tee_local $0
       (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
        (get_local $0)
        (i32.add
         (get_local $1)
         (i32.const 8)
        )
       )
      )
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 20)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 21)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 22)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (get_local $2)
    )
    (i32.const 0)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (i32.load offset=4
     (get_local $0)
    )
    (i32.add
     (get_local $1)
     (i32.const 23)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (get_local $0)
 )
 (func $_ZN21UnificationFoundationrsIN5eosio10datastreamIPKcEEEERT_S7_RNS_16unification_uapp11dataschemasE (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (get_local $0)
     )
     (i32.load offset=4
      (get_local $0)
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $1)
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 8)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
       (get_local $0)
       (i32.add
        (get_local $1)
        (i32.const 8)
       )
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 20)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (get_local $0)
    )
    (get_local $2)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 21)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (get_local $0)
    )
    (get_local $2)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 22)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (tee_local $2
    (i32.add
     (i32.load offset=4
      (get_local $0)
     )
     (i32.const 1)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (get_local $0)
    )
    (get_local $2)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $1)
     (i32.const 23)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (get_local $0)
 )
 (func $_ZNSt3__16vectorIN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_ (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.ge_u
      (tee_local $5
       (i32.add
        (tee_local $4
         (i32.div_s
          (i32.sub
           (i32.load offset=4
            (get_local $0)
           )
           (tee_local $6
            (i32.load
             (get_local $0)
            )
           )
          )
          (i32.const 24)
         )
        )
        (i32.const 1)
       )
      )
      (i32.const 178956971)
     )
    )
    (set_local $7
     (i32.const 178956970)
    )
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.gt_u
        (tee_local $6
         (i32.div_s
          (i32.sub
           (i32.load offset=8
            (get_local $0)
           )
           (get_local $6)
          )
          (i32.const 24)
         )
        )
        (i32.const 89478484)
       )
      )
      (br_if $label$2
       (i32.eqz
        (tee_local $7
         (select
          (get_local $5)
          (tee_local $7
           (i32.shl
            (get_local $6)
            (i32.const 1)
           )
          )
          (i32.lt_u
           (get_local $7)
           (get_local $5)
          )
         )
        )
       )
      )
     )
     (set_local $6
      (call $_Znwj
       (i32.mul
        (get_local $7)
        (i32.const 24)
       )
      )
     )
     (br $label$0)
    )
    (set_local $7
     (i32.const 0)
    )
    (set_local $6
     (i32.const 0)
    )
    (br $label$0)
   )
   (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
    (get_local $0)
   )
   (unreachable)
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (i32.store
   (get_local $1)
   (i32.const 0)
  )
  (i32.store
   (tee_local $1
    (i32.add
     (get_local $6)
     (i32.mul
      (get_local $4)
      (i32.const 24)
     )
    )
   )
   (get_local $5)
  )
  (i64.store offset=8
   (get_local $1)
   (i64.load
    (get_local $2)
   )
  )
  (i32.store offset=16
   (get_local $1)
   (i32.load
    (get_local $3)
   )
  )
  (set_local $4
   (i32.add
    (get_local $6)
    (i32.mul
     (get_local $7)
     (i32.const 24)
    )
   )
  )
  (set_local $5
   (i32.add
    (get_local $1)
    (i32.const 24)
   )
  )
  (block $label$4
   (block $label$5
    (br_if $label$5
     (i32.eq
      (tee_local $6
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 4)
        )
       )
      )
      (tee_local $7
       (i32.load
        (get_local $0)
       )
      )
     )
    )
    (loop $label$6
     (set_local $3
      (i32.load
       (tee_local $2
        (i32.add
         (get_local $6)
         (i32.const -24)
        )
       )
      )
     )
     (i32.store
      (get_local $2)
      (i32.const 0)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
      (get_local $3)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -8)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -8)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -12)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -12)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -16)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -16)
       )
      )
     )
     (set_local $1
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
     )
     (set_local $6
      (get_local $2)
     )
     (br_if $label$6
      (i32.ne
       (get_local $7)
       (get_local $2)
      )
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $6
     (i32.load
      (get_local $0)
     )
    )
    (br $label$4)
   )
   (set_local $6
    (get_local $7)
   )
  )
  (i32.store
   (get_local $0)
   (get_local $1)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (get_local $5)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
   (get_local $4)
  )
  (block $label$7
   (br_if $label$7
    (i32.eq
     (get_local $7)
     (get_local $6)
    )
   )
   (loop $label$8
    (set_local $1
     (i32.load
      (tee_local $7
       (i32.add
        (get_local $7)
        (i32.const -24)
       )
      )
     )
    )
    (i32.store
     (get_local $7)
     (i32.const 0)
    )
    (block $label$9
     (br_if $label$9
      (i32.eqz
       (get_local $1)
      )
     )
     (block $label$10
      (br_if $label$10
       (i32.eqz
        (i32.and
         (i32.load8_u offset=8
          (get_local $1)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 16)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $1)
     )
    )
    (br_if $label$8
     (i32.ne
      (get_local $6)
      (get_local $7)
     )
    )
   )
  )
  (block $label$11
   (br_if $label$11
    (i32.eqz
     (get_local $6)
    )
   )
   (call $_ZdlPv
    (get_local $6)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setpriceadhERKyRKhE3$_9EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (i32.store8 offset=23
   (get_local $1)
   (i32.load8_u
    (i32.load
     (get_local $3)
    )
   )
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (call $eosio_assert
   (i32.const 1)
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setpriceschERKyRKhE3$_8EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (i32.store8 offset=22
   (get_local $1)
   (i32.load8_u
    (i32.load
     (get_local $3)
    )
   )
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (call $eosio_assert
   (i32.const 1)
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_11setscheduleERKyRKhE3$_7EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (i32.store8 offset=21
   (get_local $1)
   (i32.load8_u
    (i32.load
     (get_local $3)
    )
   )
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (call $eosio_assert
   (i32.const 1)
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_7setversERKyRKhE3$_6EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (i32.store8 offset=20
   (get_local $1)
   (i32.load8_u
    (i32.load
     (get_local $3)
    )
   )
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (call $eosio_assert
   (i32.const 1)
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5boost6fusion6detail17for_each_unrolledILi6EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJyNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhhhhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJySD_hhhhEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (set_local $3
   (i32.load
    (get_local $0)
   )
  )
  (call $eosio_assert
   (i32.gt_u
    (i32.sub
     (i32.load offset=8
      (tee_local $2
       (i32.load
        (get_local $1)
       )
      )
     )
     (i32.load offset=4
      (get_local $2)
     )
    )
    (i32.const 7)
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (get_local $3)
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $2)
   (i32.add
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.load
     (get_local $1)
    )
    (i32.add
     (tee_local $2
      (i32.load
       (get_local $0)
      )
     )
     (i32.const 8)
    )
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 20)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 21)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $0
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $0)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 22)
    )
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (i32.add
    (i32.load offset=4
     (get_local $0)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $1
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $1)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $2)
     (i32.const 23)
    )
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $1)
   (i32.add
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE6modifyIZNS2_10editschemaERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEERKhSI_SI_SI_E3$_5EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i64) (param $3 i32)
  (local $4 i64)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (set_local $8
   (tee_local $7
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $7)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=24
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (set_local $4
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.load
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=21
   (get_local $1)
   (i32.load8_u
    (i32.load offset=4
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=20
   (get_local $1)
   (i32.load8_u
    (i32.load offset=8
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=22
   (get_local $1)
   (i32.load8_u
    (i32.load offset=12
     (get_local $3)
    )
   )
  )
  (i32.store8 offset=23
   (get_local $1)
   (i32.load8_u
    (i32.load offset=16
     (get_local $3)
    )
   )
  )
  (call $eosio_assert
   (i64.eq
    (get_local $4)
    (i64.load
     (get_local $1)
    )
   )
   (i32.const 448)
  )
  (set_local $3
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $3
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $3)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $3
    (i32.add
     (get_local $3)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$1
   (block $label$2
    (br_if $label$2
     (i32.lt_u
      (get_local $3)
      (i32.const 513)
     )
    )
    (set_local $7
     (call $malloc
      (get_local $3)
     )
    )
    (br $label$1)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $7
     (i32.sub
      (get_local $7)
      (i32.and
       (i32.add
        (get_local $3)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $8)
   (get_local $7)
  )
  (i32.store
   (get_local $8)
   (get_local $7)
  )
  (i32.store offset=8
   (get_local $8)
   (i32.add
    (get_local $7)
    (get_local $3)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $8)
    (get_local $1)
   )
  )
  (call $db_update_i64
   (i32.load offset=28
    (get_local $1)
   )
   (get_local $2)
   (get_local $7)
   (get_local $3)
  )
  (block $label$3
   (br_if $label$3
    (i32.lt_u
     (get_local $3)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i64.lt_u
     (get_local $4)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $4)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $4)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5boost6fusion6detail17for_each_unrolledILi5EE4callINS0_18std_tuple_iteratorINSt3__15tupleIJNS6_12basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEhhhhEEELi0EEEZN5eosiorsINSG_10datastreamIPKcEEJSD_hhhhEEERT_SN_RNS7_IJDpT0_EEEEUlSN_E_EEvRKSM_RKT0_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (drop
   (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
    (i32.load
     (get_local $1)
    )
    (i32.load
     (get_local $0)
    )
   )
  )
  (set_local $0
   (i32.load
    (get_local $0)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $2
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $2)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $0)
     (i32.const 12)
    )
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $2)
   (i32.add
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $2
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $2)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $0)
     (i32.const 13)
    )
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $2)
   (i32.add
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $2
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $2)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $0)
     (i32.const 14)
    )
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $2)
   (i32.add
    (i32.load offset=4
     (get_local $2)
    )
    (i32.const 1)
   )
  )
  (call $eosio_assert
   (i32.ne
    (i32.load offset=8
     (tee_local $1
      (i32.load
       (get_local $1)
      )
     )
    )
    (i32.load offset=4
     (get_local $1)
    )
   )
   (i32.const 128)
  )
  (drop
   (call $memcpy
    (i32.add
     (get_local $0)
     (i32.const 15)
    )
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
  (i32.store offset=4
   (get_local $1)
   (i32.add
    (i32.load offset=4
     (get_local $1)
    )
    (i32.const 1)
   )
  )
 )
 (func $_ZZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE7emplaceIZNS2_9addschemaERKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEERKhSG_SG_SG_E3$_4EENS4_14const_iteratorEyOT_ENKUlRSJ_E_clINS4_4itemEEEDaSL_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (set_local $7
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (set_local $2
   (i32.load
    (get_local $0)
   )
  )
  (block $label$0
   (br_if $label$0
    (i64.ne
     (tee_local $5
      (i64.load offset=16
       (tee_local $6
        (i32.load
         (tee_local $4
          (i32.load offset=4
           (get_local $0)
          )
         )
        )
       )
      )
     )
     (i64.const -1)
    )
   )
   (set_local $5
    (i64.const 0)
   )
   (block $label$1
    (br_if $label$1
     (i32.lt_s
      (tee_local $3
       (call $db_lowerbound_i64
        (i64.load
         (get_local $6)
        )
        (i64.load offset=8
         (get_local $6)
        )
        (i64.const 5310425802474631168)
        (i64.const 0)
       )
      )
      (i32.const 0)
     )
    )
    (drop
     (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
      (get_local $6)
      (get_local $3)
     )
    )
    (i32.store offset=4
     (get_local $7)
     (i32.const 0)
    )
    (i32.store
     (get_local $7)
     (get_local $6)
    )
    (set_local $5
     (select
      (i64.const -2)
      (i64.add
       (tee_local $5
        (i64.load
         (i32.load offset=4
          (call $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE14const_iteratormmEv
           (get_local $7)
          )
         )
        )
       )
       (i64.const 1)
      )
      (i64.gt_u
       (get_local $5)
       (i64.const -3)
      )
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $6)
     (i32.const 16)
    )
    (get_local $5)
   )
  )
  (call $eosio_assert
   (i64.lt_u
    (get_local $5)
    (i64.const -2)
   )
   (i32.const 560)
  )
  (i64.store
   (get_local $1)
   (i64.load
    (i32.add
     (get_local $6)
     (i32.const 16)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
    (i32.load offset=4
     (get_local $4)
    )
   )
  )
  (set_local $6
   (i32.load8_u
    (i32.load offset=8
     (get_local $4)
    )
   )
  )
  (i32.store8 offset=20
   (get_local $1)
   (i32.const 0)
  )
  (i32.store8 offset=21
   (get_local $1)
   (get_local $6)
  )
  (i32.store8 offset=22
   (get_local $1)
   (i32.load8_u
    (i32.load offset=12
     (get_local $4)
    )
   )
  )
  (i32.store8 offset=23
   (get_local $1)
   (i32.load8_u
    (i32.load offset=16
     (get_local $4)
    )
   )
  )
  (set_local $4
   (i32.add
    (tee_local $6
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $4
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $4)
       (i32.const 1)
      )
     )
    )
    (i32.const 12)
   )
  )
  (set_local $5
   (i64.extend_u/i32
    (get_local $6)
   )
  )
  (loop $label$2
   (set_local $4
    (i32.add
     (get_local $4)
     (i32.const 1)
    )
   )
   (br_if $label$2
    (i64.ne
     (tee_local $5
      (i64.shr_u
       (get_local $5)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$3
   (block $label$4
    (br_if $label$4
     (i32.lt_u
      (get_local $4)
      (i32.const 513)
     )
    )
    (set_local $6
     (call $malloc
      (get_local $4)
     )
    )
    (br $label$3)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $6
     (i32.sub
      (get_local $8)
      (i32.and
       (i32.add
        (get_local $4)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store offset=4
   (get_local $7)
   (get_local $6)
  )
  (i32.store
   (get_local $7)
   (get_local $6)
  )
  (i32.store offset=8
   (get_local $7)
   (i32.add
    (get_local $6)
    (get_local $4)
   )
  )
  (drop
   (call $_ZN21UnificationFoundationlsIN5eosio10datastreamIPcEEEERT_S6_RKNS_16unification_uapp11dataschemasE
    (get_local $7)
    (get_local $1)
   )
  )
  (i32.store offset=28
   (get_local $1)
   (call $db_store_i64
    (i64.load offset=8
     (get_local $2)
    )
    (i64.const 5310425802474631168)
    (i64.load
     (i32.load offset=8
      (get_local $0)
     )
    )
    (tee_local $5
     (i64.load
      (get_local $1)
     )
    )
    (get_local $6)
    (get_local $4)
   )
  )
  (block $label$5
   (br_if $label$5
    (i32.lt_u
     (get_local $4)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $6)
   )
  )
  (block $label$6
   (br_if $label$6
    (i64.lt_u
     (get_local $5)
     (i64.load offset=16
      (get_local $2)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $2)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $5)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $5)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $7)
    (i32.const 16)
   )
  )
 )
 (func $_ZN5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE14const_iteratormmEv (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $2
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (tee_local $1
       (i32.load offset=4
        (get_local $0)
       )
      )
     )
    )
    (call $eosio_assert
     (i32.xor
      (i32.shr_u
       (tee_local $1
        (call $db_previous_i64
         (i32.load offset=28
          (get_local $1)
         )
         (i32.add
          (get_local $2)
          (i32.const 8)
         )
        )
       )
       (i32.const 31)
      )
      (i32.const 1)
     )
     (i32.const 688)
    )
    (br $label$0)
   )
   (call $eosio_assert
    (i32.ne
     (tee_local $1
      (call $db_end_i64
       (i64.load
        (tee_local $1
         (i32.load
          (get_local $0)
         )
        )
       )
       (i64.load offset=8
        (get_local $1)
       )
       (i64.const 5310425802474631168)
      )
     )
     (i32.const -1)
    )
    (i32.const 624)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $1
       (call $db_previous_i64
        (get_local $1)
        (i32.add
         (get_local $2)
         (i32.const 8)
        )
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 624)
   )
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (call $_ZNK5eosio11multi_indexILy5310425802474631168EN21UnificationFoundation16unification_uapp11dataschemasEJEE31load_object_by_primary_iteratorEl
    (i32.load
     (get_local $0)
    )
    (get_local $1)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $2)
    (i32.const 16)
   )
  )
  (get_local $0)
 )
 (func $_ZNK5eosio11multi_indexILy12299097112569344000EN21UnificationFoundation16unification_uapp11permrecordsEJEE31load_object_by_primary_iteratorEl (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $8
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 32)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $9)
  )
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $7
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 28)
       )
      )
     )
     (tee_local $2
      (i32.load offset=24
       (get_local $0)
      )
     )
    )
   )
   (set_local $3
    (i32.sub
     (i32.const 0)
     (get_local $2)
    )
   )
   (set_local $6
    (i32.add
     (get_local $7)
     (i32.const -24)
    )
   )
   (loop $label$1
    (br_if $label$0
     (i32.eq
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
    (set_local $7
     (get_local $6)
    )
    (set_local $6
     (tee_local $4
      (i32.add
       (get_local $6)
       (i32.const -24)
      )
     )
    )
    (br_if $label$1
     (i32.ne
      (i32.add
       (get_local $4)
       (get_local $3)
      )
      (i32.const -24)
     )
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.eq
      (get_local $7)
      (get_local $2)
     )
    )
    (set_local $6
     (i32.load
      (i32.add
       (get_local $7)
       (i32.const -24)
      )
     )
    )
    (br $label$2)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $4
       (call $db_get_i64
        (get_local $1)
        (i32.const 0)
        (i32.const 0)
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 528)
   )
   (block $label$4
    (block $label$5
     (br_if $label$5
      (i32.le_u
       (get_local $4)
       (i32.const 512)
      )
     )
     (drop
      (call $db_get_i64
       (get_local $1)
       (tee_local $7
        (call $malloc
         (get_local $4)
        )
       )
       (get_local $4)
      )
     )
     (call $free
      (get_local $7)
     )
     (br $label$4)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $7
      (i32.sub
       (get_local $9)
       (i32.and
        (i32.add
         (get_local $4)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
    (drop
     (call $db_get_i64
      (get_local $1)
      (get_local $7)
      (get_local $4)
     )
    )
   )
   (i32.store offset=16
    (tee_local $6
     (call $_Znwj
      (i32.const 32)
     )
    )
    (get_local $0)
   )
   (call $eosio_assert
    (i32.gt_u
     (get_local $4)
     (i32.const 7)
    )
    (i32.const 128)
   )
   (drop
    (call $memcpy
     (get_local $6)
     (get_local $7)
     (i32.const 8)
    )
   )
   (call $eosio_assert
    (i32.ne
     (get_local $4)
     (i32.const 8)
    )
    (i32.const 128)
   )
   (drop
    (call $memcpy
     (i32.add
      (get_local $6)
      (i32.const 8)
     )
     (i32.add
      (get_local $7)
      (i32.const 8)
     )
     (i32.const 1)
    )
   )
   (i32.store offset=20
    (get_local $6)
    (get_local $1)
   )
   (i32.store offset=24
    (get_local $8)
    (get_local $6)
   )
   (i64.store offset=16
    (get_local $8)
    (tee_local $5
     (i64.load
      (get_local $6)
     )
    )
   )
   (i32.store offset=12
    (get_local $8)
    (tee_local $7
     (i32.load offset=20
      (get_local $6)
     )
    )
   )
   (block $label$6
    (block $label$7
     (br_if $label$7
      (i32.ge_u
       (tee_local $4
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 32)
        )
       )
      )
     )
     (i64.store offset=8
      (get_local $4)
      (get_local $5)
     )
     (i32.store offset=16
      (get_local $4)
      (get_local $7)
     )
     (i32.store offset=24
      (get_local $8)
      (i32.const 0)
     )
     (i32.store
      (get_local $4)
      (get_local $6)
     )
     (i32.store
      (get_local $1)
      (i32.add
       (get_local $4)
       (i32.const 24)
      )
     )
     (br $label$6)
    )
    (call $_ZNSt3__16vectorIN5eosio11multi_indexILy12299097112569344000EN21UnificationFoundation16unification_uapp11permrecordsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
     (i32.add
      (get_local $0)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 16)
     )
     (i32.add
      (get_local $8)
      (i32.const 12)
     )
    )
   )
   (set_local $4
    (i32.load offset=24
     (get_local $8)
    )
   )
   (i32.store offset=24
    (get_local $8)
    (i32.const 0)
   )
   (br_if $label$2
    (i32.eqz
     (get_local $4)
    )
   )
   (call $_ZdlPv
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 32)
   )
  )
  (get_local $6)
 )
 (func $_ZNSt3__16vectorIN5eosio11multi_indexILy12299097112569344000EN21UnificationFoundation16unification_uapp11permrecordsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_ (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.ge_u
      (tee_local $5
       (i32.add
        (tee_local $4
         (i32.div_s
          (i32.sub
           (i32.load offset=4
            (get_local $0)
           )
           (tee_local $6
            (i32.load
             (get_local $0)
            )
           )
          )
          (i32.const 24)
         )
        )
        (i32.const 1)
       )
      )
      (i32.const 178956971)
     )
    )
    (set_local $7
     (i32.const 178956970)
    )
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.gt_u
        (tee_local $6
         (i32.div_s
          (i32.sub
           (i32.load offset=8
            (get_local $0)
           )
           (get_local $6)
          )
          (i32.const 24)
         )
        )
        (i32.const 89478484)
       )
      )
      (br_if $label$2
       (i32.eqz
        (tee_local $7
         (select
          (get_local $5)
          (tee_local $7
           (i32.shl
            (get_local $6)
            (i32.const 1)
           )
          )
          (i32.lt_u
           (get_local $7)
           (get_local $5)
          )
         )
        )
       )
      )
     )
     (set_local $6
      (call $_Znwj
       (i32.mul
        (get_local $7)
        (i32.const 24)
       )
      )
     )
     (br $label$0)
    )
    (set_local $7
     (i32.const 0)
    )
    (set_local $6
     (i32.const 0)
    )
    (br $label$0)
   )
   (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
    (get_local $0)
   )
   (unreachable)
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (i32.store
   (get_local $1)
   (i32.const 0)
  )
  (i32.store
   (tee_local $1
    (i32.add
     (get_local $6)
     (i32.mul
      (get_local $4)
      (i32.const 24)
     )
    )
   )
   (get_local $5)
  )
  (i64.store offset=8
   (get_local $1)
   (i64.load
    (get_local $2)
   )
  )
  (i32.store offset=16
   (get_local $1)
   (i32.load
    (get_local $3)
   )
  )
  (set_local $4
   (i32.add
    (get_local $6)
    (i32.mul
     (get_local $7)
     (i32.const 24)
    )
   )
  )
  (set_local $5
   (i32.add
    (get_local $1)
    (i32.const 24)
   )
  )
  (block $label$4
   (block $label$5
    (br_if $label$5
     (i32.eq
      (tee_local $6
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 4)
        )
       )
      )
      (tee_local $7
       (i32.load
        (get_local $0)
       )
      )
     )
    )
    (loop $label$6
     (set_local $3
      (i32.load
       (tee_local $2
        (i32.add
         (get_local $6)
         (i32.const -24)
        )
       )
      )
     )
     (i32.store
      (get_local $2)
      (i32.const 0)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
      (get_local $3)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -8)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -8)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -12)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -12)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -16)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -16)
       )
      )
     )
     (set_local $1
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
     )
     (set_local $6
      (get_local $2)
     )
     (br_if $label$6
      (i32.ne
       (get_local $7)
       (get_local $2)
      )
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $6
     (i32.load
      (get_local $0)
     )
    )
    (br $label$4)
   )
   (set_local $6
    (get_local $7)
   )
  )
  (i32.store
   (get_local $0)
   (get_local $1)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (get_local $5)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
   (get_local $4)
  )
  (block $label$7
   (br_if $label$7
    (i32.eq
     (get_local $7)
     (get_local $6)
    )
   )
   (loop $label$8
    (set_local $1
     (i32.load
      (tee_local $7
       (i32.add
        (get_local $7)
        (i32.const -24)
       )
      )
     )
    )
    (i32.store
     (get_local $7)
     (i32.const 0)
    )
    (block $label$9
     (br_if $label$9
      (i32.eqz
       (get_local $1)
      )
     )
     (call $_ZdlPv
      (get_local $1)
     )
    )
    (br_if $label$8
     (i32.ne
      (get_local $6)
      (get_local $7)
     )
    )
   )
  )
  (block $label$10
   (br_if $label$10
    (i32.eqz
     (get_local $6)
    )
   )
   (call $_ZdlPv
    (get_local $6)
   )
  )
 )
 (func $_ZN5boost4mp116detail16tuple_apply_implIRZN5eosio14execute_actionIN21UnificationFoundation16unification_uappES6_JRKyRKNSt3__112basic_stringIcNS9_11char_traitsIcEENS9_9allocatorIcEEEESH_EEEbPT_MT0_FvDpT1_EEUlDpT_E_RNS9_5tupleIJySF_SF_EEEJLj0ELj1ELj2EEEEDTclclsr3stdE7forwardISI_Efp_Espclsr3stdE3getIXT1_EEclsr3stdE7forwardISK_Efp0_EEEEOSI_OSK_NS0_16integer_sequenceIjJXspT1_EEEE (param $0 i32) (param $1 i32)
  (local $2 i64)
  (local $3 i32)
  (local $4 i32)
  (i32.store offset=4
   (i32.const 0)
   (tee_local $4
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (set_local $2
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $4)
     (i32.const 24)
    )
    (i32.add
     (get_local $1)
     (i32.const 8)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_
    (i32.add
     (get_local $4)
     (i32.const 8)
    )
    (i32.add
     (get_local $1)
     (i32.const 20)
    )
   )
  )
  (i64.store offset=40
   (get_local $4)
   (get_local $2)
  )
  (set_local $0
   (i32.add
    (i32.load
     (i32.load
      (get_local $0)
     )
    )
    (i32.shr_s
     (tee_local $3
      (i32.load offset=4
       (tee_local $1
        (i32.load offset=4
         (get_local $0)
        )
       )
      )
     )
     (i32.const 1)
    )
   )
  )
  (set_local $1
   (i32.load
    (get_local $1)
   )
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (i32.and
      (get_local $3)
      (i32.const 1)
     )
    )
   )
   (set_local $1
    (i32.load
     (i32.add
      (i32.load
       (get_local $0)
      )
      (get_local $1)
     )
    )
   )
  )
  (call_indirect (type $FUNCSIG$viiii)
   (get_local $0)
   (i32.add
    (get_local $4)
    (i32.const 40)
   )
   (i32.add
    (get_local $4)
    (i32.const 24)
   )
   (i32.add
    (get_local $4)
    (i32.const 8)
   )
   (get_local $1)
  )
  (block $label$1
   (br_if $label$1
    (i32.eqz
     (i32.and
      (i32.load8_u offset=8
       (get_local $4)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=16
     (get_local $4)
    )
   )
  )
  (block $label$2
   (br_if $label$2
    (i32.eqz
     (i32.and
      (i32.load8_u offset=24
       (get_local $4)
      )
      (i32.const 1)
     )
    )
   )
   (call $_ZdlPv
    (i32.load offset=32
     (get_local $4)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $4)
    (i32.const 48)
   )
  )
 )
 (func $_ZNK5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE31load_object_by_primary_iteratorEl (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i64)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $8
   (tee_local $9
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 48)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $9)
  )
  (block $label$0
   (br_if $label$0
    (i32.eq
     (tee_local $7
      (i32.load
       (i32.add
        (get_local $0)
        (i32.const 28)
       )
      )
     )
     (tee_local $2
      (i32.load offset=24
       (get_local $0)
      )
     )
    )
   )
   (set_local $3
    (i32.sub
     (i32.const 0)
     (get_local $2)
    )
   )
   (set_local $6
    (i32.add
     (get_local $7)
     (i32.const -24)
    )
   )
   (loop $label$1
    (br_if $label$0
     (i32.eq
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const 16)
       )
      )
      (get_local $1)
     )
    )
    (set_local $7
     (get_local $6)
    )
    (set_local $6
     (tee_local $4
      (i32.add
       (get_local $6)
       (i32.const -24)
      )
     )
    )
    (br_if $label$1
     (i32.ne
      (i32.add
       (get_local $4)
       (get_local $3)
      )
      (i32.const -24)
     )
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.eq
      (get_local $7)
      (get_local $2)
     )
    )
    (set_local $6
     (i32.load
      (i32.add
       (get_local $7)
       (i32.const -24)
      )
     )
    )
    (br $label$2)
   )
   (call $eosio_assert
    (i32.xor
     (i32.shr_u
      (tee_local $6
       (call $db_get_i64
        (get_local $1)
        (i32.const 0)
        (i32.const 0)
       )
      )
      (i32.const 31)
     )
     (i32.const 1)
    )
    (i32.const 528)
   )
   (block $label$4
    (block $label$5
     (br_if $label$5
      (i32.lt_u
       (get_local $6)
       (i32.const 513)
      )
     )
     (set_local $4
      (call $malloc
       (get_local $6)
      )
     )
     (br $label$4)
    )
    (i32.store offset=4
     (i32.const 0)
     (tee_local $4
      (i32.sub
       (get_local $9)
       (i32.and
        (i32.add
         (get_local $6)
         (i32.const 15)
        )
        (i32.const -16)
       )
      )
     )
    )
   )
   (drop
    (call $db_get_i64
     (get_local $1)
     (get_local $4)
     (get_local $6)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=32
    (get_local $8)
    (get_local $4)
   )
   (i32.store offset=40
    (get_local $8)
    (tee_local $7
     (i32.add
      (get_local $4)
      (get_local $6)
     )
    )
   )
   (block $label$6
    (br_if $label$6
     (i32.le_u
      (get_local $6)
      (i32.const 512)
     )
    )
    (call $free
     (get_local $4)
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $8)
       (i32.const 40)
      )
     )
    )
    (set_local $4
     (i32.load offset=36
      (get_local $8)
     )
    )
   )
   (i64.store offset=8 align=4
    (tee_local $6
     (call $_Znwj
      (i32.const 48)
     )
    )
    (i64.const 0)
   )
   (i64.store offset=16 align=4
    (get_local $6)
    (i64.const 0)
   )
   (i64.store offset=24 align=4
    (get_local $6)
    (i64.const 0)
   )
   (i32.store offset=32
    (get_local $6)
    (get_local $0)
   )
   (call $eosio_assert
    (i32.gt_u
     (i32.sub
      (get_local $7)
      (get_local $4)
     )
     (i32.const 7)
    )
    (i32.const 128)
   )
   (drop
    (call $memcpy
     (get_local $6)
     (get_local $4)
     (i32.const 8)
    )
   )
   (i32.store offset=36
    (get_local $8)
    (i32.add
     (get_local $4)
     (i32.const 8)
    )
   )
   (drop
    (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
     (call $_ZN5eosiorsINS_10datastreamIPKcEEEERT_S6_RNSt3__112basic_stringIcNS7_11char_traitsIcEENS7_9allocatorIcEEEE
      (i32.add
       (get_local $8)
       (i32.const 32)
      )
      (i32.add
       (get_local $6)
       (i32.const 8)
      )
     )
     (i32.add
      (get_local $6)
      (i32.const 20)
     )
    )
   )
   (i32.store offset=36
    (get_local $6)
    (get_local $1)
   )
   (i32.store offset=24
    (get_local $8)
    (get_local $6)
   )
   (i64.store offset=16
    (get_local $8)
    (tee_local $5
     (i64.load
      (get_local $6)
     )
    )
   )
   (i32.store offset=12
    (get_local $8)
    (tee_local $7
     (i32.load offset=36
      (get_local $6)
     )
    )
   )
   (block $label$7
    (block $label$8
     (br_if $label$8
      (i32.ge_u
       (tee_local $4
        (i32.load
         (tee_local $1
          (i32.add
           (get_local $0)
           (i32.const 28)
          )
         )
        )
       )
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 32)
        )
       )
      )
     )
     (i64.store offset=8
      (get_local $4)
      (get_local $5)
     )
     (i32.store offset=16
      (get_local $4)
      (get_local $7)
     )
     (i32.store offset=24
      (get_local $8)
      (i32.const 0)
     )
     (i32.store
      (get_local $4)
      (get_local $6)
     )
     (i32.store
      (get_local $1)
      (i32.add
       (get_local $4)
       (i32.const 24)
      )
     )
     (br $label$7)
    )
    (call $_ZNSt3__16vectorIN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_
     (i32.add
      (get_local $0)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 24)
     )
     (i32.add
      (get_local $8)
      (i32.const 16)
     )
     (i32.add
      (get_local $8)
      (i32.const 12)
     )
    )
   )
   (set_local $4
    (i32.load offset=24
     (get_local $8)
    )
   )
   (i32.store offset=24
    (get_local $8)
    (i32.const 0)
   )
   (br_if $label$2
    (i32.eqz
     (get_local $4)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eqz
      (i32.and
       (i32.load8_u offset=20
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 28)
      )
     )
    )
   )
   (block $label$10
    (br_if $label$10
     (i32.eqz
      (i32.and
       (i32.load8_u offset=8
        (get_local $4)
       )
       (i32.const 1)
      )
     )
    )
    (call $_ZdlPv
     (i32.load
      (i32.add
       (get_local $4)
       (i32.const 16)
      )
     )
    )
   )
   (call $_ZdlPv
    (get_local $4)
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $8)
    (i32.const 48)
   )
  )
  (get_local $6)
 )
 (func $_ZN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE6modifyIZNS2_10updatepermERKyRKNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEESG_E3$_1EEvRKS3_yOT_ (param $0 i32) (param $1 i32) (param $2 i32)
  (local $3 i64)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i64)
  (local $8 i32)
  (local $9 i32)
  (set_local $9
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (call $eosio_assert
   (i32.eq
    (i32.load offset=32
     (get_local $1)
    )
    (get_local $0)
   )
   (i32.const 336)
  )
  (call $eosio_assert
   (i64.eq
    (i64.load
     (get_local $0)
    )
    (call $current_receiver)
   )
   (i32.const 384)
  )
  (set_local $3
   (i64.load
    (get_local $1)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (tee_local $4
     (i32.add
      (get_local $1)
      (i32.const 8)
     )
    )
    (i32.load
     (get_local $2)
    )
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
    (tee_local $5
     (i32.add
      (get_local $1)
      (i32.const 20)
     )
    )
    (i32.load offset=4
     (get_local $2)
    )
   )
  )
  (call $eosio_assert
   (i64.eq
    (get_local $3)
    (i64.load
     (get_local $1)
    )
   )
   (i32.const 448)
  )
  (set_local $2
   (i32.add
    (tee_local $6
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $2
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $2)
       (i32.const 1)
      )
     )
    )
    (i32.const 8)
   )
  )
  (set_local $7
   (i64.extend_u/i32
    (get_local $6)
   )
  )
  (loop $label$0
   (set_local $2
    (i32.add
     (get_local $2)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $7
      (i64.shr_u
       (get_local $7)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (set_local $2
   (i32.add
    (tee_local $6
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 24)
       )
      )
      (i32.shr_u
       (tee_local $6
        (i32.load8_u
         (i32.add
          (get_local $1)
          (i32.const 20)
         )
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $6)
       (i32.const 1)
      )
     )
    )
    (get_local $2)
   )
  )
  (set_local $7
   (i64.extend_u/i32
    (get_local $6)
   )
  )
  (loop $label$1
   (set_local $2
    (i32.add
     (get_local $2)
     (i32.const 1)
    )
   )
   (br_if $label$1
    (i64.ne
     (tee_local $7
      (i64.shr_u
       (get_local $7)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.lt_u
      (get_local $2)
      (i32.const 513)
     )
    )
    (set_local $8
     (call $malloc
      (get_local $2)
     )
    )
    (br $label$2)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $8
     (i32.sub
      (get_local $8)
      (i32.and
       (i32.add
        (get_local $2)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store
   (get_local $9)
   (get_local $8)
  )
  (i32.store offset=8
   (get_local $9)
   (i32.add
    (get_local $8)
    (get_local $2)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (get_local $2)
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $8)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $9)
   (i32.add
    (get_local $8)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
    (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
     (get_local $9)
     (get_local $4)
    )
    (get_local $5)
   )
  )
  (call $db_update_i64
   (i32.load offset=36
    (get_local $1)
   )
   (i64.const 0)
   (get_local $8)
   (get_local $2)
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $2)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $8)
   )
  )
  (block $label$5
   (br_if $label$5
    (i64.lt_u
     (get_local $3)
     (i64.load offset=16
      (get_local $0)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $0)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $3)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $3)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $9)
    (i32.const 16)
   )
  )
 )
 (func $_ZNSt3__16vectorIN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE8item_ptrENS_9allocatorIS7_EEE24__emplace_back_slow_pathIJNS_10unique_ptrINS6_4itemENS_14default_deleteISD_EEEERyRlEEEvDpOT_ (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.ge_u
      (tee_local $5
       (i32.add
        (tee_local $4
         (i32.div_s
          (i32.sub
           (i32.load offset=4
            (get_local $0)
           )
           (tee_local $6
            (i32.load
             (get_local $0)
            )
           )
          )
          (i32.const 24)
         )
        )
        (i32.const 1)
       )
      )
      (i32.const 178956971)
     )
    )
    (set_local $7
     (i32.const 178956970)
    )
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.gt_u
        (tee_local $6
         (i32.div_s
          (i32.sub
           (i32.load offset=8
            (get_local $0)
           )
           (get_local $6)
          )
          (i32.const 24)
         )
        )
        (i32.const 89478484)
       )
      )
      (br_if $label$2
       (i32.eqz
        (tee_local $7
         (select
          (get_local $5)
          (tee_local $7
           (i32.shl
            (get_local $6)
            (i32.const 1)
           )
          )
          (i32.lt_u
           (get_local $7)
           (get_local $5)
          )
         )
        )
       )
      )
     )
     (set_local $6
      (call $_Znwj
       (i32.mul
        (get_local $7)
        (i32.const 24)
       )
      )
     )
     (br $label$0)
    )
    (set_local $7
     (i32.const 0)
    )
    (set_local $6
     (i32.const 0)
    )
    (br $label$0)
   )
   (call $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv
    (get_local $0)
   )
   (unreachable)
  )
  (set_local $5
   (i32.load
    (get_local $1)
   )
  )
  (i32.store
   (get_local $1)
   (i32.const 0)
  )
  (i32.store
   (tee_local $1
    (i32.add
     (get_local $6)
     (i32.mul
      (get_local $4)
      (i32.const 24)
     )
    )
   )
   (get_local $5)
  )
  (i64.store offset=8
   (get_local $1)
   (i64.load
    (get_local $2)
   )
  )
  (i32.store offset=16
   (get_local $1)
   (i32.load
    (get_local $3)
   )
  )
  (set_local $4
   (i32.add
    (get_local $6)
    (i32.mul
     (get_local $7)
     (i32.const 24)
    )
   )
  )
  (set_local $5
   (i32.add
    (get_local $1)
    (i32.const 24)
   )
  )
  (block $label$4
   (block $label$5
    (br_if $label$5
     (i32.eq
      (tee_local $6
       (i32.load
        (i32.add
         (get_local $0)
         (i32.const 4)
        )
       )
      )
      (tee_local $7
       (i32.load
        (get_local $0)
       )
      )
     )
    )
    (loop $label$6
     (set_local $3
      (i32.load
       (tee_local $2
        (i32.add
         (get_local $6)
         (i32.const -24)
        )
       )
      )
     )
     (i32.store
      (get_local $2)
      (i32.const 0)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
      (get_local $3)
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -8)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -8)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -12)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -12)
       )
      )
     )
     (i32.store
      (i32.add
       (get_local $1)
       (i32.const -16)
      )
      (i32.load
       (i32.add
        (get_local $6)
        (i32.const -16)
       )
      )
     )
     (set_local $1
      (i32.add
       (get_local $1)
       (i32.const -24)
      )
     )
     (set_local $6
      (get_local $2)
     )
     (br_if $label$6
      (i32.ne
       (get_local $7)
       (get_local $2)
      )
     )
    )
    (set_local $7
     (i32.load
      (i32.add
       (get_local $0)
       (i32.const 4)
      )
     )
    )
    (set_local $6
     (i32.load
      (get_local $0)
     )
    )
    (br $label$4)
   )
   (set_local $6
    (get_local $7)
   )
  )
  (i32.store
   (get_local $0)
   (get_local $1)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 4)
   )
   (get_local $5)
  )
  (i32.store
   (i32.add
    (get_local $0)
    (i32.const 8)
   )
   (get_local $4)
  )
  (block $label$7
   (br_if $label$7
    (i32.eq
     (get_local $7)
     (get_local $6)
    )
   )
   (loop $label$8
    (set_local $1
     (i32.load
      (tee_local $7
       (i32.add
        (get_local $7)
        (i32.const -24)
       )
      )
     )
    )
    (i32.store
     (get_local $7)
     (i32.const 0)
    )
    (block $label$9
     (br_if $label$9
      (i32.eqz
       (get_local $1)
      )
     )
     (block $label$10
      (br_if $label$10
       (i32.eqz
        (i32.and
         (i32.load8_u offset=20
          (get_local $1)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 28)
        )
       )
      )
     )
     (block $label$11
      (br_if $label$11
       (i32.eqz
        (i32.and
         (i32.load8_u offset=8
          (get_local $1)
         )
         (i32.const 1)
        )
       )
      )
      (call $_ZdlPv
       (i32.load
        (i32.add
         (get_local $1)
         (i32.const 16)
        )
       )
      )
     )
     (call $_ZdlPv
      (get_local $1)
     )
    )
    (br_if $label$8
     (i32.ne
      (get_local $6)
      (get_local $7)
     )
    )
   )
  )
  (block $label$12
   (br_if $label$12
    (i32.eqz
     (get_local $6)
    )
   )
   (call $_ZdlPv
    (get_local $6)
   )
  )
 )
 (func $_ZZN5eosio11multi_indexILy15426370973263200256EN21UnificationFoundation16unification_uapp9userpermsEJEE7emplaceIZNS2_8initpermERKyE3$_0EENS4_14const_iteratorEyOT_ENKUlRSA_E_clINS4_4itemEEEDaSC_ (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i64)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (set_local $9
   (tee_local $8
    (i32.sub
     (i32.load offset=4
      (i32.const 0)
     )
     (i32.const 16)
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (get_local $8)
  )
  (i64.store
   (get_local $1)
   (i64.load
    (i32.load
     (i32.load offset=4
      (get_local $0)
     )
    )
   )
  )
  (set_local $2
   (i32.load
    (get_local $0)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc
    (tee_local $3
     (i32.add
      (get_local $1)
      (i32.const 8)
     )
    )
    (i32.const 1072)
   )
  )
  (drop
   (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc
    (tee_local $4
     (i32.add
      (get_local $1)
      (i32.const 20)
     )
    )
    (i32.const 1072)
   )
  )
  (set_local $7
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 12)
       )
      )
      (i32.shr_u
       (tee_local $7
        (i32.load8_u offset=8
         (get_local $1)
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $7)
       (i32.const 1)
      )
     )
    )
    (i32.const 8)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$0
   (set_local $7
    (i32.add
     (get_local $7)
     (i32.const 1)
    )
   )
   (br_if $label$0
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (set_local $7
   (i32.add
    (tee_local $5
     (select
      (i32.load
       (i32.add
        (get_local $1)
        (i32.const 24)
       )
      )
      (i32.shr_u
       (tee_local $5
        (i32.load8_u
         (i32.add
          (get_local $1)
          (i32.const 20)
         )
        )
       )
       (i32.const 1)
      )
      (i32.and
       (get_local $5)
       (i32.const 1)
      )
     )
    )
    (get_local $7)
   )
  )
  (set_local $6
   (i64.extend_u/i32
    (get_local $5)
   )
  )
  (loop $label$1
   (set_local $7
    (i32.add
     (get_local $7)
     (i32.const 1)
    )
   )
   (br_if $label$1
    (i64.ne
     (tee_local $6
      (i64.shr_u
       (get_local $6)
       (i64.const 7)
      )
     )
     (i64.const 0)
    )
   )
  )
  (block $label$2
   (block $label$3
    (br_if $label$3
     (i32.lt_u
      (get_local $7)
      (i32.const 513)
     )
    )
    (set_local $8
     (call $malloc
      (get_local $7)
     )
    )
    (br $label$2)
   )
   (i32.store offset=4
    (i32.const 0)
    (tee_local $8
     (i32.sub
      (get_local $8)
      (i32.and
       (i32.add
        (get_local $7)
        (i32.const 15)
       )
       (i32.const -16)
      )
     )
    )
   )
  )
  (i32.store
   (get_local $9)
   (get_local $8)
  )
  (i32.store offset=8
   (get_local $9)
   (i32.add
    (get_local $8)
    (get_local $7)
   )
  )
  (call $eosio_assert
   (i32.gt_s
    (get_local $7)
    (i32.const 7)
   )
   (i32.const 512)
  )
  (drop
   (call $memcpy
    (get_local $8)
    (get_local $1)
    (i32.const 8)
   )
  )
  (i32.store offset=4
   (get_local $9)
   (i32.add
    (get_local $8)
    (i32.const 8)
   )
  )
  (drop
   (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
    (call $_ZN5eosiolsINS_10datastreamIPcEEEERT_S5_RKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE
     (get_local $9)
     (get_local $3)
    )
    (get_local $4)
   )
  )
  (i32.store offset=36
   (get_local $1)
   (call $db_store_i64
    (i64.load offset=8
     (get_local $2)
    )
    (i64.const -3020373100446351360)
    (i64.load
     (i32.load offset=8
      (get_local $0)
     )
    )
    (tee_local $6
     (i64.load
      (get_local $1)
     )
    )
    (get_local $8)
    (get_local $7)
   )
  )
  (block $label$4
   (br_if $label$4
    (i32.lt_u
     (get_local $7)
     (i32.const 513)
    )
   )
   (call $free
    (get_local $8)
   )
  )
  (block $label$5
   (br_if $label$5
    (i64.lt_u
     (get_local $6)
     (i64.load offset=16
      (get_local $2)
     )
    )
   )
   (i64.store
    (i32.add
     (get_local $2)
     (i32.const 16)
    )
    (select
     (i64.const -2)
     (i64.add
      (get_local $6)
      (i64.const 1)
     )
     (i64.gt_u
      (get_local $6)
      (i64.const -3)
     )
    )
   )
  )
  (i32.store offset=4
   (i32.const 0)
   (i32.add
    (get_local $9)
    (i32.const 16)
   )
  )
 )
 (func $_ZN21UnificationFoundation16unification_uappC2Ey (param $0 i32) (param $1 i64) (result i32)
  (i64.store
   (get_local $0)
   (get_local $1)
  )
  (get_local $0)
 )
 (func $malloc (param $0 i32) (result i32)
  (call $_ZN5eosio14memory_manager6mallocEm
   (i32.const 1120)
   (get_local $0)
  )
 )
 (func $_ZN5eosio14memory_manager6mallocEm (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (local $9 i32)
  (local $10 i32)
  (local $11 i32)
  (local $12 i32)
  (local $13 i32)
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (get_local $1)
    )
   )
   (block $label$1
    (br_if $label$1
     (tee_local $13
      (i32.load offset=8384
       (get_local $0)
      )
     )
    )
    (set_local $13
     (i32.const 16)
    )
    (i32.store
     (i32.add
      (get_local $0)
      (i32.const 8384)
     )
     (i32.const 16)
    )
   )
   (set_local $2
    (select
     (i32.sub
      (i32.add
       (get_local $1)
       (i32.const 8)
      )
      (tee_local $2
       (i32.and
        (i32.add
         (get_local $1)
         (i32.const 4)
        )
        (i32.const 7)
       )
      )
     )
     (get_local $1)
     (get_local $2)
    )
   )
   (block $label$2
    (block $label$3
     (block $label$4
      (br_if $label$4
       (i32.ge_u
        (tee_local $10
         (i32.load offset=8388
          (get_local $0)
         )
        )
        (get_local $13)
       )
      )
      (set_local $1
       (i32.add
        (i32.add
         (get_local $0)
         (i32.mul
          (get_local $10)
          (i32.const 12)
         )
        )
        (i32.const 8192)
       )
      )
      (block $label$5
       (br_if $label$5
        (get_local $10)
       )
       (br_if $label$5
        (i32.load
         (tee_local $13
          (i32.add
           (get_local $0)
           (i32.const 8196)
          )
         )
        )
       )
       (i32.store
        (get_local $1)
        (i32.const 8192)
       )
       (i32.store
        (get_local $13)
        (get_local $0)
       )
      )
      (set_local $10
       (i32.add
        (get_local $2)
        (i32.const 4)
       )
      )
      (loop $label$6
       (block $label$7
        (br_if $label$7
         (i32.gt_u
          (i32.add
           (tee_local $13
            (i32.load offset=8
             (get_local $1)
            )
           )
           (get_local $10)
          )
          (i32.load
           (get_local $1)
          )
         )
        )
        (i32.store
         (tee_local $13
          (i32.add
           (i32.load offset=4
            (get_local $1)
           )
           (get_local $13)
          )
         )
         (i32.or
          (i32.and
           (i32.load
            (get_local $13)
           )
           (i32.const -2147483648)
          )
          (get_local $2)
         )
        )
        (i32.store
         (tee_local $1
          (i32.add
           (get_local $1)
           (i32.const 8)
          )
         )
         (i32.add
          (i32.load
           (get_local $1)
          )
          (get_local $10)
         )
        )
        (i32.store
         (get_local $13)
         (i32.or
          (i32.load
           (get_local $13)
          )
          (i32.const -2147483648)
         )
        )
        (br_if $label$3
         (tee_local $1
          (i32.add
           (get_local $13)
           (i32.const 4)
          )
         )
        )
       )
       (br_if $label$6
        (tee_local $1
         (call $_ZN5eosio14memory_manager16next_active_heapEv
          (get_local $0)
         )
        )
       )
      )
     )
     (set_local $4
      (i32.sub
       (i32.const 2147483644)
       (get_local $2)
      )
     )
     (set_local $11
      (i32.add
       (get_local $0)
       (i32.const 8392)
      )
     )
     (set_local $12
      (i32.add
       (get_local $0)
       (i32.const 8384)
      )
     )
     (set_local $13
      (tee_local $3
       (i32.load offset=8392
        (get_local $0)
       )
      )
     )
     (loop $label$8
      (call $eosio_assert
       (i32.eq
        (i32.load
         (i32.add
          (tee_local $1
           (i32.add
            (get_local $0)
            (i32.mul
             (get_local $13)
             (i32.const 12)
            )
           )
          )
          (i32.const 8200)
         )
        )
        (i32.load
         (tee_local $5
          (i32.add
           (get_local $1)
           (i32.const 8192)
          )
         )
        )
       )
       (i32.const 9520)
      )
      (set_local $13
       (i32.add
        (tee_local $6
         (i32.load
          (i32.add
           (get_local $1)
           (i32.const 8196)
          )
         )
        )
        (i32.const 4)
       )
      )
      (loop $label$9
       (set_local $7
        (i32.add
         (get_local $6)
         (i32.load
          (get_local $5)
         )
        )
       )
       (set_local $1
        (i32.and
         (tee_local $9
          (i32.load
           (tee_local $8
            (i32.add
             (get_local $13)
             (i32.const -4)
            )
           )
          )
         )
         (i32.const 2147483647)
        )
       )
       (block $label$10
        (br_if $label$10
         (i32.lt_s
          (get_local $9)
          (i32.const 0)
         )
        )
        (block $label$11
         (br_if $label$11
          (i32.ge_u
           (get_local $1)
           (get_local $2)
          )
         )
         (loop $label$12
          (br_if $label$11
           (i32.ge_u
            (tee_local $10
             (i32.add
              (get_local $13)
              (get_local $1)
             )
            )
            (get_local $7)
           )
          )
          (br_if $label$11
           (i32.lt_s
            (tee_local $10
             (i32.load
              (get_local $10)
             )
            )
            (i32.const 0)
           )
          )
          (br_if $label$12
           (i32.lt_u
            (tee_local $1
             (i32.add
              (i32.add
               (get_local $1)
               (i32.and
                (get_local $10)
                (i32.const 2147483647)
               )
              )
              (i32.const 4)
             )
            )
            (get_local $2)
           )
          )
         )
        )
        (i32.store
         (get_local $8)
         (i32.or
          (select
           (get_local $1)
           (get_local $2)
           (i32.lt_u
            (get_local $1)
            (get_local $2)
           )
          )
          (i32.and
           (get_local $9)
           (i32.const -2147483648)
          )
         )
        )
        (block $label$13
         (br_if $label$13
          (i32.le_u
           (get_local $1)
           (get_local $2)
          )
         )
         (i32.store
          (i32.add
           (get_local $13)
           (get_local $2)
          )
          (i32.and
           (i32.add
            (get_local $4)
            (get_local $1)
           )
           (i32.const 2147483647)
          )
         )
        )
        (br_if $label$2
         (i32.ge_u
          (get_local $1)
          (get_local $2)
         )
        )
       )
       (br_if $label$9
        (i32.lt_u
         (tee_local $13
          (i32.add
           (i32.add
            (get_local $13)
            (get_local $1)
           )
           (i32.const 4)
          )
         )
         (get_local $7)
        )
       )
      )
      (set_local $1
       (i32.const 0)
      )
      (i32.store
       (get_local $11)
       (tee_local $13
        (select
         (i32.const 0)
         (tee_local $13
          (i32.add
           (i32.load
            (get_local $11)
           )
           (i32.const 1)
          )
         )
         (i32.eq
          (get_local $13)
          (i32.load
           (get_local $12)
          )
         )
        )
       )
      )
      (br_if $label$8
       (i32.ne
        (get_local $13)
        (get_local $3)
       )
      )
     )
    )
    (return
     (get_local $1)
    )
   )
   (i32.store
    (get_local $8)
    (i32.or
     (i32.load
      (get_local $8)
     )
     (i32.const -2147483648)
    )
   )
   (return
    (get_local $13)
   )
  )
  (i32.const 0)
 )
 (func $_ZN5eosio14memory_manager16next_active_heapEv (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (local $8 i32)
  (set_local $1
   (i32.load offset=8388
    (get_local $0)
   )
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (i32.load8_u offset=9606
       (i32.const 0)
      )
     )
    )
    (set_local $7
     (i32.load offset=9608
      (i32.const 0)
     )
    )
    (br $label$0)
   )
   (set_local $7
    (current_memory)
   )
   (i32.store8 offset=9606
    (i32.const 0)
    (i32.const 1)
   )
   (i32.store offset=9608
    (i32.const 0)
    (tee_local $7
     (i32.shl
      (get_local $7)
      (i32.const 16)
     )
    )
   )
  )
  (set_local $3
   (get_local $7)
  )
  (block $label$2
   (block $label$3
    (block $label$4
     (block $label$5
      (br_if $label$5
       (i32.le_u
        (tee_local $2
         (i32.shr_u
          (i32.add
           (get_local $7)
           (i32.const 65535)
          )
          (i32.const 16)
         )
        )
        (tee_local $8
         (current_memory)
        )
       )
      )
      (drop
       (grow_memory
        (i32.sub
         (get_local $2)
         (get_local $8)
        )
       )
      )
      (set_local $8
       (i32.const 0)
      )
      (br_if $label$4
       (i32.ne
        (get_local $2)
        (current_memory)
       )
      )
      (set_local $3
       (i32.load offset=9608
        (i32.const 0)
       )
      )
     )
     (set_local $8
      (i32.const 0)
     )
     (i32.store offset=9608
      (i32.const 0)
      (get_local $3)
     )
     (br_if $label$4
      (i32.lt_s
       (get_local $7)
       (i32.const 0)
      )
     )
     (set_local $2
      (i32.add
       (get_local $0)
       (i32.mul
        (get_local $1)
        (i32.const 12)
       )
      )
     )
     (set_local $7
      (i32.sub
       (i32.sub
        (i32.add
         (get_local $7)
         (select
          (i32.const 65536)
          (i32.const 131072)
          (tee_local $6
           (i32.lt_u
            (tee_local $8
             (i32.and
              (get_local $7)
              (i32.const 65535)
             )
            )
            (i32.const 64513)
           )
          )
         )
        )
        (select
         (get_local $8)
         (i32.and
          (get_local $7)
          (i32.const 131071)
         )
         (get_local $6)
        )
       )
       (get_local $7)
      )
     )
     (block $label$6
      (br_if $label$6
       (i32.load8_u offset=9606
        (i32.const 0)
       )
      )
      (set_local $3
       (current_memory)
      )
      (i32.store8 offset=9606
       (i32.const 0)
       (i32.const 1)
      )
      (i32.store offset=9608
       (i32.const 0)
       (tee_local $3
        (i32.shl
         (get_local $3)
         (i32.const 16)
        )
       )
      )
     )
     (set_local $2
      (i32.add
       (get_local $2)
       (i32.const 8192)
      )
     )
     (br_if $label$3
      (i32.lt_s
       (get_local $7)
       (i32.const 0)
      )
     )
     (set_local $6
      (get_local $3)
     )
     (block $label$7
      (br_if $label$7
       (i32.le_u
        (tee_local $8
         (i32.shr_u
          (i32.add
           (i32.add
            (tee_local $5
             (i32.and
              (i32.add
               (get_local $7)
               (i32.const 7)
              )
              (i32.const -8)
             )
            )
            (get_local $3)
           )
           (i32.const 65535)
          )
          (i32.const 16)
         )
        )
        (tee_local $4
         (current_memory)
        )
       )
      )
      (drop
       (grow_memory
        (i32.sub
         (get_local $8)
         (get_local $4)
        )
       )
      )
      (br_if $label$3
       (i32.ne
        (get_local $8)
        (current_memory)
       )
      )
      (set_local $6
       (i32.load offset=9608
        (i32.const 0)
       )
      )
     )
     (i32.store offset=9608
      (i32.const 0)
      (i32.add
       (get_local $6)
       (get_local $5)
      )
     )
     (br_if $label$3
      (i32.eq
       (get_local $3)
       (i32.const -1)
      )
     )
     (br_if $label$2
      (i32.eq
       (i32.add
        (tee_local $6
         (i32.load
          (i32.add
           (tee_local $1
            (i32.add
             (get_local $0)
             (i32.mul
              (get_local $1)
              (i32.const 12)
             )
            )
           )
           (i32.const 8196)
          )
         )
        )
        (tee_local $8
         (i32.load
          (get_local $2)
         )
        )
       )
       (get_local $3)
      )
     )
     (block $label$8
      (br_if $label$8
       (i32.eq
        (get_local $8)
        (tee_local $1
         (i32.load
          (tee_local $5
           (i32.add
            (get_local $1)
            (i32.const 8200)
           )
          )
         )
        )
       )
      )
      (i32.store
       (tee_local $6
        (i32.add
         (get_local $6)
         (get_local $1)
        )
       )
       (i32.or
        (i32.and
         (i32.load
          (get_local $6)
         )
         (i32.const -2147483648)
        )
        (i32.add
         (i32.sub
          (i32.const -4)
          (get_local $1)
         )
         (get_local $8)
        )
       )
      )
      (i32.store
       (get_local $5)
       (i32.load
        (get_local $2)
       )
      )
      (i32.store
       (get_local $6)
       (i32.and
        (i32.load
         (get_local $6)
        )
        (i32.const 2147483647)
       )
      )
     )
     (i32.store
      (tee_local $2
       (i32.add
        (get_local $0)
        (i32.const 8388)
       )
      )
      (tee_local $2
       (i32.add
        (i32.load
         (get_local $2)
        )
        (i32.const 1)
       )
      )
     )
     (i32.store
      (i32.add
       (tee_local $0
        (i32.add
         (get_local $0)
         (i32.mul
          (get_local $2)
          (i32.const 12)
         )
        )
       )
       (i32.const 8196)
      )
      (get_local $3)
     )
     (i32.store
      (tee_local $8
       (i32.add
        (get_local $0)
        (i32.const 8192)
       )
      )
      (get_local $7)
     )
    )
    (return
     (get_local $8)
    )
   )
   (block $label$9
    (br_if $label$9
     (i32.eq
      (tee_local $8
       (i32.load
        (get_local $2)
       )
      )
      (tee_local $7
       (i32.load
        (tee_local $1
         (i32.add
          (tee_local $3
           (i32.add
            (get_local $0)
            (i32.mul
             (get_local $1)
             (i32.const 12)
            )
           )
          )
          (i32.const 8200)
         )
        )
       )
      )
     )
    )
    (i32.store
     (tee_local $3
      (i32.add
       (i32.load
        (i32.add
         (get_local $3)
         (i32.const 8196)
        )
       )
       (get_local $7)
      )
     )
     (i32.or
      (i32.and
       (i32.load
        (get_local $3)
       )
       (i32.const -2147483648)
      )
      (i32.add
       (i32.sub
        (i32.const -4)
        (get_local $7)
       )
       (get_local $8)
      )
     )
    )
    (i32.store
     (get_local $1)
     (i32.load
      (get_local $2)
     )
    )
    (i32.store
     (get_local $3)
     (i32.and
      (i32.load
       (get_local $3)
      )
      (i32.const 2147483647)
     )
    )
   )
   (i32.store offset=8384
    (get_local $0)
    (tee_local $3
     (i32.add
      (i32.load
       (tee_local $7
        (i32.add
         (get_local $0)
         (i32.const 8388)
        )
       )
      )
      (i32.const 1)
     )
    )
   )
   (i32.store
    (get_local $7)
    (get_local $3)
   )
   (return
    (i32.const 0)
   )
  )
  (i32.store
   (get_local $2)
   (i32.add
    (get_local $8)
    (get_local $7)
   )
  )
  (get_local $2)
 )
 (func $free (param $0 i32)
  (local $1 i32)
  (local $2 i32)
  (local $3 i32)
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (get_local $0)
     )
    )
    (br_if $label$1
     (i32.lt_s
      (tee_local $2
       (i32.load offset=9504
        (i32.const 0)
       )
      )
      (i32.const 1)
     )
    )
    (set_local $3
     (i32.const 9312)
    )
    (set_local $1
     (i32.add
      (i32.mul
       (get_local $2)
       (i32.const 12)
      )
      (i32.const 9312)
     )
    )
    (loop $label$2
     (br_if $label$1
      (i32.eqz
       (tee_local $2
        (i32.load
         (i32.add
          (get_local $3)
          (i32.const 4)
         )
        )
       )
      )
     )
     (block $label$3
      (br_if $label$3
       (i32.gt_u
        (i32.add
         (get_local $2)
         (i32.const 4)
        )
        (get_local $0)
       )
      )
      (br_if $label$0
       (i32.gt_u
        (i32.add
         (get_local $2)
         (i32.load
          (get_local $3)
         )
        )
        (get_local $0)
       )
      )
     )
     (br_if $label$2
      (i32.lt_u
       (tee_local $3
        (i32.add
         (get_local $3)
         (i32.const 12)
        )
       )
       (get_local $1)
      )
     )
    )
   )
   (return)
  )
  (i32.store
   (tee_local $3
    (i32.add
     (get_local $0)
     (i32.const -4)
    )
   )
   (i32.and
    (i32.load
     (get_local $3)
    )
    (i32.const 2147483647)
   )
  )
 )
 (func $_Znwj (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (block $label$0
   (br_if $label$0
    (tee_local $0
     (call $malloc
      (tee_local $1
       (select
        (get_local $0)
        (i32.const 1)
        (get_local $0)
       )
      )
     )
    )
   )
   (loop $label$1
    (set_local $0
     (i32.const 0)
    )
    (br_if $label$0
     (i32.eqz
      (tee_local $2
       (i32.load offset=9612
        (i32.const 0)
       )
      )
     )
    )
    (call_indirect (type $FUNCSIG$v)
     (get_local $2)
    )
    (br_if $label$1
     (i32.eqz
      (tee_local $0
       (call $malloc
        (get_local $1)
       )
      )
     )
    )
   )
  )
  (get_local $0)
 )
 (func $_ZdlPv (param $0 i32)
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (get_local $0)
    )
   )
   (call $free
    (get_local $0)
   )
  )
 )
 (func $_ZNKSt3__121__basic_string_commonILb1EE20__throw_length_errorEv (param $0 i32)
  (call $abort)
  (unreachable)
 )
 (func $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_ (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (block $label$0
   (block $label$1
    (block $label$2
     (block $label$3
      (br_if $label$3
       (i32.eq
        (get_local $0)
        (get_local $1)
       )
      )
      (set_local $2
       (select
        (i32.load offset=4
         (get_local $1)
        )
        (i32.shr_u
         (tee_local $2
          (i32.load8_u
           (get_local $1)
          )
         )
         (i32.const 1)
        )
        (tee_local $4
         (i32.and
          (get_local $2)
          (i32.const 1)
         )
        )
       )
      )
      (set_local $5
       (i32.add
        (get_local $1)
        (i32.const 1)
       )
      )
      (set_local $6
       (i32.load offset=8
        (get_local $1)
       )
      )
      (set_local $1
       (i32.const 10)
      )
      (block $label$4
       (br_if $label$4
        (i32.eqz
         (i32.and
          (tee_local $3
           (i32.load8_u
            (get_local $0)
           )
          )
          (i32.const 1)
         )
        )
       )
       (set_local $1
        (i32.add
         (i32.and
          (tee_local $3
           (i32.load
            (get_local $0)
           )
          )
          (i32.const -2)
         )
         (i32.const -1)
        )
       )
      )
      (set_local $5
       (select
        (get_local $6)
        (get_local $5)
        (get_local $4)
       )
      )
      (set_local $4
       (i32.and
        (get_local $3)
        (i32.const 1)
       )
      )
      (block $label$5
       (block $label$6
        (block $label$7
         (br_if $label$7
          (i32.le_u
           (get_local $2)
           (get_local $1)
          )
         )
         (br_if $label$6
          (get_local $4)
         )
         (set_local $3
          (i32.shr_u
           (i32.and
            (get_local $3)
            (i32.const 254)
           )
           (i32.const 1)
          )
         )
         (br $label$5)
        )
        (br_if $label$2
         (get_local $4)
        )
        (set_local $1
         (i32.add
          (get_local $0)
          (i32.const 1)
         )
        )
        (br_if $label$1
         (get_local $2)
        )
        (br $label$0)
       )
       (set_local $3
        (i32.load offset=4
         (get_local $0)
        )
       )
      )
      (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE21__grow_by_and_replaceEjjjjjjPKc
       (get_local $0)
       (get_local $1)
       (i32.sub
        (get_local $2)
        (get_local $1)
       )
       (get_local $3)
       (i32.const 0)
       (get_local $3)
       (get_local $2)
       (get_local $5)
      )
     )
     (return
      (get_local $0)
     )
    )
    (set_local $1
     (i32.load offset=8
      (get_local $0)
     )
    )
    (br_if $label$0
     (i32.eqz
      (get_local $2)
     )
    )
   )
   (drop
    (call $memmove
     (get_local $1)
     (get_local $5)
     (get_local $2)
    )
   )
  )
  (i32.store8
   (i32.add
    (get_local $1)
    (get_local $2)
   )
   (i32.const 0)
  )
  (block $label$8
   (br_if $label$8
    (i32.and
     (i32.load8_u
      (get_local $0)
     )
     (i32.const 1)
    )
   )
   (i32.store8
    (get_local $0)
    (i32.shl
     (get_local $2)
     (i32.const 1)
    )
   )
   (return
    (get_local $0)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (get_local $2)
  )
  (get_local $0)
 )
 (func $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE21__grow_by_and_replaceEjjjjjjPKc (param $0 i32) (param $1 i32) (param $2 i32) (param $3 i32) (param $4 i32) (param $5 i32) (param $6 i32) (param $7 i32)
  (local $8 i32)
  (local $9 i32)
  (local $10 i32)
  (block $label$0
   (br_if $label$0
    (i32.lt_u
     (i32.sub
      (i32.const -18)
      (get_local $1)
     )
     (get_local $2)
    )
   )
   (block $label$1
    (block $label$2
     (br_if $label$2
      (i32.and
       (i32.load8_u
        (get_local $0)
       )
       (i32.const 1)
      )
     )
     (set_local $9
      (i32.add
       (get_local $0)
       (i32.const 1)
      )
     )
     (br $label$1)
    )
    (set_local $9
     (i32.load offset=8
      (get_local $0)
     )
    )
   )
   (set_local $10
    (i32.const -17)
   )
   (block $label$3
    (br_if $label$3
     (i32.gt_u
      (get_local $1)
      (i32.const 2147483622)
     )
    )
    (set_local $10
     (i32.const 11)
    )
    (br_if $label$3
     (i32.lt_u
      (tee_local $2
       (select
        (tee_local $8
         (i32.shl
          (get_local $1)
          (i32.const 1)
         )
        )
        (tee_local $2
         (i32.add
          (get_local $2)
          (get_local $1)
         )
        )
        (i32.lt_u
         (get_local $2)
         (get_local $8)
        )
       )
      )
      (i32.const 11)
     )
    )
    (set_local $10
     (i32.and
      (i32.add
       (get_local $2)
       (i32.const 16)
      )
      (i32.const -16)
     )
    )
   )
   (set_local $2
    (call $_Znwj
     (get_local $10)
    )
   )
   (block $label$4
    (br_if $label$4
     (i32.eqz
      (get_local $4)
     )
    )
    (drop
     (call $memcpy
      (get_local $2)
      (get_local $9)
      (get_local $4)
     )
    )
   )
   (block $label$5
    (br_if $label$5
     (i32.eqz
      (get_local $6)
     )
    )
    (drop
     (call $memcpy
      (i32.add
       (get_local $2)
       (get_local $4)
      )
      (get_local $7)
      (get_local $6)
     )
    )
   )
   (block $label$6
    (br_if $label$6
     (i32.eqz
      (tee_local $7
       (i32.sub
        (tee_local $3
         (i32.sub
          (get_local $3)
          (get_local $5)
         )
        )
        (get_local $4)
       )
      )
     )
    )
    (drop
     (call $memcpy
      (i32.add
       (i32.add
        (get_local $2)
        (get_local $4)
       )
       (get_local $6)
      )
      (i32.add
       (i32.add
        (get_local $9)
        (get_local $4)
       )
       (get_local $5)
      )
      (get_local $7)
     )
    )
   )
   (block $label$7
    (br_if $label$7
     (i32.eq
      (get_local $1)
      (i32.const 10)
     )
    )
    (call $_ZdlPv
     (get_local $9)
    )
   )
   (i32.store offset=8
    (get_local $0)
    (get_local $2)
   )
   (i32.store
    (get_local $0)
    (i32.or
     (get_local $10)
     (i32.const 1)
    )
   )
   (i32.store offset=4
    (get_local $0)
    (tee_local $4
     (i32.add
      (get_local $3)
      (get_local $6)
     )
    )
   )
   (i32.store8
    (i32.add
     (get_local $2)
     (get_local $4)
    )
    (i32.const 0)
   )
   (return)
  )
  (call $abort)
  (unreachable)
 )
 (func $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEj (param $0 i32) (param $1 i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (local $6 i32)
  (local $7 i32)
  (block $label$0
   (br_if $label$0
    (i32.ge_u
     (get_local $1)
     (i32.const -16)
    )
   )
   (set_local $2
    (i32.const 10)
   )
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (i32.and
       (tee_local $5
        (i32.load8_u
         (get_local $0)
        )
       )
       (i32.const 1)
      )
     )
    )
    (set_local $2
     (i32.add
      (i32.and
       (tee_local $5
        (i32.load
         (get_local $0)
        )
       )
       (i32.const -2)
      )
      (i32.const -1)
     )
    )
   )
   (block $label$2
    (block $label$3
     (br_if $label$3
      (i32.and
       (get_local $5)
       (i32.const 1)
      )
     )
     (set_local $3
      (i32.shr_u
       (i32.and
        (get_local $5)
        (i32.const 254)
       )
       (i32.const 1)
      )
     )
     (br $label$2)
    )
    (set_local $3
     (i32.load offset=4
      (get_local $0)
     )
    )
   )
   (set_local $4
    (i32.const 10)
   )
   (block $label$4
    (br_if $label$4
     (i32.lt_u
      (tee_local $1
       (select
        (get_local $3)
        (get_local $1)
        (i32.gt_u
         (get_local $3)
         (get_local $1)
        )
       )
      )
      (i32.const 11)
     )
    )
    (set_local $4
     (i32.add
      (i32.and
       (i32.add
        (get_local $1)
        (i32.const 16)
       )
       (i32.const -16)
      )
      (i32.const -1)
     )
    )
   )
   (block $label$5
    (br_if $label$5
     (i32.eq
      (get_local $4)
      (get_local $2)
     )
    )
    (block $label$6
     (block $label$7
      (br_if $label$7
       (i32.ne
        (get_local $4)
        (i32.const 10)
       )
      )
      (set_local $6
       (i32.const 1)
      )
      (set_local $1
       (i32.add
        (get_local $0)
        (i32.const 1)
       )
      )
      (set_local $2
       (i32.load offset=8
        (get_local $0)
       )
      )
      (set_local $7
       (i32.const 0)
      )
      (br $label$6)
     )
     (set_local $1
      (call $_Znwj
       (i32.add
        (get_local $4)
        (i32.const 1)
       )
      )
     )
     (block $label$8
      (br_if $label$8
       (i32.gt_u
        (get_local $4)
        (get_local $2)
       )
      )
      (br_if $label$5
       (i32.eqz
        (get_local $1)
       )
      )
     )
     (block $label$9
      (br_if $label$9
       (i32.and
        (tee_local $5
         (i32.load8_u
          (get_local $0)
         )
        )
        (i32.const 1)
       )
      )
      (set_local $7
       (i32.const 1)
      )
      (set_local $2
       (i32.add
        (get_local $0)
        (i32.const 1)
       )
      )
      (set_local $6
       (i32.const 0)
      )
      (br $label$6)
     )
     (set_local $2
      (i32.load offset=8
       (get_local $0)
      )
     )
     (set_local $6
      (i32.const 1)
     )
     (set_local $7
      (i32.const 1)
     )
    )
    (block $label$10
     (block $label$11
      (br_if $label$11
       (i32.and
        (get_local $5)
        (i32.const 1)
       )
      )
      (set_local $5
       (i32.shr_u
        (i32.and
         (get_local $5)
         (i32.const 254)
        )
        (i32.const 1)
       )
      )
      (br $label$10)
     )
     (set_local $5
      (i32.load offset=4
       (get_local $0)
      )
     )
    )
    (block $label$12
     (br_if $label$12
      (i32.eqz
       (tee_local $5
        (i32.add
         (get_local $5)
         (i32.const 1)
        )
       )
      )
     )
     (drop
      (call $memcpy
       (get_local $1)
       (get_local $2)
       (get_local $5)
      )
     )
    )
    (block $label$13
     (br_if $label$13
      (i32.eqz
       (get_local $6)
      )
     )
     (call $_ZdlPv
      (get_local $2)
     )
    )
    (block $label$14
     (br_if $label$14
      (i32.eqz
       (get_local $7)
      )
     )
     (i32.store offset=4
      (get_local $0)
      (get_local $3)
     )
     (i32.store offset=8
      (get_local $0)
      (get_local $1)
     )
     (i32.store
      (get_local $0)
      (i32.or
       (i32.add
        (get_local $4)
        (i32.const 1)
       )
       (i32.const 1)
      )
     )
     (return)
    )
    (i32.store8
     (get_local $0)
     (i32.shl
      (get_local $3)
      (i32.const 1)
     )
    )
   )
   (return)
  )
  (call $abort)
  (unreachable)
 )
 (func $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (set_local $2
   (call $strlen
    (get_local $1)
   )
  )
  (set_local $5
   (i32.const 10)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (i32.and
      (tee_local $3
       (i32.load8_u
        (get_local $0)
       )
      )
      (i32.const 1)
     )
    )
   )
   (set_local $5
    (i32.add
     (i32.and
      (tee_local $3
       (i32.load
        (get_local $0)
       )
      )
      (i32.const -2)
     )
     (i32.const -1)
    )
   )
  )
  (set_local $4
   (i32.and
    (get_local $3)
    (i32.const 1)
   )
  )
  (block $label$1
   (block $label$2
    (block $label$3
     (block $label$4
      (block $label$5
       (block $label$6
        (br_if $label$6
         (i32.le_u
          (get_local $2)
          (get_local $5)
         )
        )
        (br_if $label$5
         (get_local $4)
        )
        (set_local $3
         (i32.shr_u
          (i32.and
           (get_local $3)
           (i32.const 254)
          )
          (i32.const 1)
         )
        )
        (br $label$4)
       )
       (br_if $label$3
        (get_local $4)
       )
       (set_local $5
        (i32.add
         (get_local $0)
         (i32.const 1)
        )
       )
       (br_if $label$2
        (get_local $2)
       )
       (br $label$1)
      )
      (set_local $3
       (i32.load offset=4
        (get_local $0)
       )
      )
     )
     (call $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE21__grow_by_and_replaceEjjjjjjPKc
      (get_local $0)
      (get_local $5)
      (i32.sub
       (get_local $2)
       (get_local $5)
      )
      (get_local $3)
      (i32.const 0)
      (get_local $3)
      (get_local $2)
      (get_local $1)
     )
     (return
      (get_local $0)
     )
    )
    (set_local $5
     (i32.load offset=8
      (get_local $0)
     )
    )
    (br_if $label$1
     (i32.eqz
      (get_local $2)
     )
    )
   )
   (drop
    (call $memmove
     (get_local $5)
     (get_local $1)
     (get_local $2)
    )
   )
  )
  (i32.store8
   (i32.add
    (get_local $5)
    (get_local $2)
   )
   (i32.const 0)
  )
  (block $label$7
   (br_if $label$7
    (i32.and
     (i32.load8_u
      (get_local $0)
     )
     (i32.const 1)
    )
   )
   (i32.store8
    (get_local $0)
    (i32.shl
     (get_local $2)
     (i32.const 1)
    )
   )
   (return
    (get_local $0)
   )
  )
  (i32.store offset=4
   (get_local $0)
   (get_local $2)
  )
  (get_local $0)
 )
 (func $_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv (param $0 i32)
  (call $abort)
  (unreachable)
 )
 (func $_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_ (param $0 i32) (param $1 i32) (result i32)
  (local $2 i32)
  (local $3 i32)
  (local $4 i32)
  (i64.store align=4
   (get_local $0)
   (i64.const 0)
  )
  (i32.store
   (tee_local $3
    (i32.add
     (get_local $0)
     (i32.const 8)
    )
   )
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.and
     (i32.load8_u
      (get_local $1)
     )
     (i32.const 1)
    )
   )
   (i64.store align=4
    (get_local $0)
    (i64.load align=4
     (get_local $1)
    )
   )
   (i32.store
    (get_local $3)
    (i32.load
     (i32.add
      (get_local $1)
      (i32.const 8)
     )
    )
   )
   (return
    (get_local $0)
   )
  )
  (block $label$1
   (br_if $label$1
    (i32.ge_u
     (tee_local $3
      (i32.load offset=4
       (get_local $1)
      )
     )
     (i32.const -16)
    )
   )
   (set_local $2
    (i32.load offset=8
     (get_local $1)
    )
   )
   (block $label$2
    (block $label$3
     (block $label$4
      (br_if $label$4
       (i32.ge_u
        (get_local $3)
        (i32.const 11)
       )
      )
      (i32.store8
       (get_local $0)
       (i32.shl
        (get_local $3)
        (i32.const 1)
       )
      )
      (set_local $1
       (i32.add
        (get_local $0)
        (i32.const 1)
       )
      )
      (br_if $label$3
       (get_local $3)
      )
      (br $label$2)
     )
     (set_local $1
      (call $_Znwj
       (tee_local $4
        (i32.and
         (i32.add
          (get_local $3)
          (i32.const 16)
         )
         (i32.const -16)
        )
       )
      )
     )
     (i32.store
      (get_local $0)
      (i32.or
       (get_local $4)
       (i32.const 1)
      )
     )
     (i32.store offset=8
      (get_local $0)
      (get_local $1)
     )
     (i32.store offset=4
      (get_local $0)
      (get_local $3)
     )
    )
    (drop
     (call $memcpy
      (get_local $1)
      (get_local $2)
      (get_local $3)
     )
    )
   )
   (i32.store8
    (i32.add
     (get_local $1)
     (get_local $3)
    )
    (i32.const 0)
   )
   (return
    (get_local $0)
   )
  )
  (call $abort)
  (unreachable)
 )
 (func $strlen (param $0 i32) (result i32)
  (local $1 i32)
  (local $2 i32)
  (set_local $2
   (get_local $0)
  )
  (block $label$0
   (block $label$1
    (br_if $label$1
     (i32.eqz
      (i32.and
       (get_local $0)
       (i32.const 3)
      )
     )
    )
    (set_local $2
     (get_local $0)
    )
    (loop $label$2
     (br_if $label$0
      (i32.eqz
       (i32.load8_u
        (get_local $2)
       )
      )
     )
     (br_if $label$2
      (i32.and
       (tee_local $2
        (i32.add
         (get_local $2)
         (i32.const 1)
        )
       )
       (i32.const 3)
      )
     )
    )
   )
   (set_local $2
    (i32.add
     (get_local $2)
     (i32.const -4)
    )
   )
   (loop $label$3
    (br_if $label$3
     (i32.eqz
      (i32.and
       (i32.and
        (i32.xor
         (tee_local $1
          (i32.load
           (tee_local $2
            (i32.add
             (get_local $2)
             (i32.const 4)
            )
           )
          )
         )
         (i32.const -1)
        )
        (i32.add
         (get_local $1)
         (i32.const -16843009)
        )
       )
       (i32.const -2139062144)
      )
     )
    )
   )
   (br_if $label$0
    (i32.eqz
     (i32.and
      (get_local $1)
      (i32.const 255)
     )
    )
   )
   (loop $label$4
    (br_if $label$4
     (i32.load8_u
      (tee_local $2
       (i32.add
        (get_local $2)
        (i32.const 1)
       )
      )
     )
    )
   )
  )
  (i32.sub
   (get_local $2)
   (get_local $0)
  )
 )
 (func $memcmp (param $0 i32) (param $1 i32) (param $2 i32) (result i32)
  (local $3 i32)
  (local $4 i32)
  (local $5 i32)
  (set_local $5
   (i32.const 0)
  )
  (block $label$0
   (br_if $label$0
    (i32.eqz
     (get_local $2)
    )
   )
   (block $label$1
    (loop $label$2
     (br_if $label$1
      (i32.ne
       (tee_local $3
        (i32.load8_u
         (get_local $0)
        )
       )
       (tee_local $4
        (i32.load8_u
         (get_local $1)
        )
       )
      )
     )
     (set_local $1
      (i32.add
       (get_local $1)
       (i32.const 1)
      )
     )
     (set_local $0
      (i32.add
       (get_local $0)
       (i32.const 1)
      )
     )
     (br_if $label$2
      (tee_local $2
       (i32.add
        (get_local $2)
        (i32.const -1)
       )
      )
     )
     (br $label$0)
    )
   )
   (set_local $5
    (i32.sub
     (get_local $3)
     (get_local $4)
    )
   )
  )
  (get_local $5)
 )
 (func $__wasm_nullptr (type $FUNCSIG$v)
  (unreachable)
 )
)
