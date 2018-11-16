/**
 *  @file unification_mother.cpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include "unification_mother.hpp"

namespace UnificationFoundation {

    using namespace eosio;
    using eosio::indexed_by;
    using eosio::const_mem_fun;

/**
 *  @defgroup unification_mother MOTHER Contract
 *  @brief Contains validated apps in Unification system
 *
 *  @details
 *
 */

    unification_mother::unification_mother(action_name self) : contract(self) {}

    void unification_mother::addnew(const account_name uapp_contract_acc,
                                      const std::string ipfs_hash) {

        eosio::print(name{_self}, " Called addnew()");

        // make sure authorised by unification
        eosio::require_auth(_self);

        valapps v_apps(_self, _self);

        auto itr = v_apps.find(uapp_contract_acc);

        if (itr == v_apps.end()) {
            //no record for app exists yet. Create one
            v_apps.emplace(_self /*payer*/, [&](auto &v_rec) {
                v_rec.uapp_contract_acc = uapp_contract_acc;
                v_rec.ipfs_hash = ipfs_hash;
                v_rec.is_valid = 1;
            });
        } else {
            //requesting app already has record. Update
            v_apps.modify(itr, _self /*payer*/, [&](auto &v_rec) {
                v_rec.ipfs_hash = ipfs_hash;
                v_rec.is_valid = 1;
            });
        }

    }

    void unification_mother::validate(const account_name uapp_contract_acc) {

        // make sure authorised by unification
        require_auth(_self);

        valapps v_apps(_self, _self);

        // verify already exist
        auto itr = v_apps.find(uapp_contract_acc);
        eosio_assert(itr != v_apps.end(), "Address for account not found");

        v_apps.modify(itr, _self /*payer*/, [&](auto &v_rec) {
            v_rec.is_valid = 1;
        });

    }

    void unification_mother::invalidate(const account_name uapp_contract_acc) {

        // make sure authorised by unification
        require_auth(_self);

        valapps v_apps(_self, _self);

        // verify already exist
        auto itr = v_apps.find(uapp_contract_acc);
        eosio_assert(itr != v_apps.end(), "Address for account not found");

        v_apps.modify(itr, _self /*payer*/, [&](auto &v_rec) {
            v_rec.is_valid = 0;
        });

    }
}