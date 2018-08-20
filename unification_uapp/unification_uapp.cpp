/**
 *  @file unification_uapp.cpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include "unification_uapp.hpp"

namespace UnificationFoundation {

    using namespace eosio;
    using eosio::indexed_by;
    using eosio::const_mem_fun;

/**
 *  @defgroup unification_uapp3 Unification Access Control Contract
 *  @brief Defines user controlled access to data
 *
 *  @details
 *  Each app requesting data from THIS app is assigned a container in the contract,
 *  which can contain a growing list of users who have granted them access.
 *  Only users can call the grant/revoke functions to modify their status for a requesting app
 */

    unification_uapp::unification_uapp(action_name self) : contract(self) {}

    void unification_uapp::grant(const account_name user_account,
                                const account_name requesting_app) {

        eosio::print(name{user_account}, " Called grant()");

        // make sure authorised by user. Only user can grant access to their data
        require_auth(user_account);

        set_permission(user_account,requesting_app,1);
    }

    void unification_uapp::revoke(const account_name user_account,
                                 const account_name requesting_app) {

        eosio::print(name{user_account}, " Called revoke()");

        // make sure authorised by user. Only user can revoke access to their data
        require_auth(user_account);

        set_permission(user_account,requesting_app,0);

    }

    void unification_uapp::set_permission(const account_name user_account, const account_name requesting_app, int permission) {

        // make sure authorised by user. Only user can revoke access to their data
        require_auth(user_account);

        // code, scope. Scope = requesting app.
        unifperms perms(_self, requesting_app);

        auto itr = perms.find(user_account);
        if (itr == perms.end()) {
            //no record for requesting app exists yet. Create one
            eosio::print(name{user_account}, " added ",permission," record for ", name{requesting_app});
            perms.emplace(_self /*payer*/, [&](auto &p_rec) {
                p_rec.user_account = user_account;
                p_rec.permission_granted = permission;
            });
        } else {
            //requesting app already has record for user. Update its user perms
            eosio::print(name{user_account}, " set access to ",permission," for ", name{requesting_app});
            perms.modify(itr, _self /*payer*/, [&](auto &p_rec) {
                p_rec.permission_granted = permission;
            });
        }
    }

    void unification_uapp::addschema(std::string schema, uint8_t schema_vers, uint8_t schedule, uint8_t min_und) {
        eosio::print("addschema()");

        require_auth(_self);

        unifschemas u_schema(_self, _self);

        u_schema.emplace(_self, [&]( auto& s_rec ) {
            s_rec.pkey = u_schema.available_primary_key();
            s_rec.schema = schema;
            s_rec.schedule = schedule;
            s_rec.schema_vers = 0;
            s_rec.min_und = min_und;
        });
    }

    void unification_uapp::editschema(uint64_t pkey, std::string schema, uint8_t schema_vers, uint8_t schedule, uint8_t min_und) {

    }

    void unification_uapp::initreq(uint64_t source_name, uint64_t schema_id, uint8_t req_type, std::string query, uint8_t user_und) {

    }

    void unification_uapp::updatereq(uint64_t pkey, std::string hash, std::string aggr) {

    }


}
