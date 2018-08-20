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

    void unification_uapp::modifyperm(account_name user_account, account_name requesting_app, uint8_t level) {

        // make sure authorised by user. Only user can modify access to their data
        require_auth(user_account);

        // code, scope. Scope = requesting app.
        unifperms perms(_self, requesting_app);

        auto itr = perms.find(user_account);
        if (itr == perms.end()) {
            //no record for requesting app exists yet. Create one
            perms.emplace(_self /*payer*/, [&](auto &p_rec) {
                p_rec.user_account = user_account;
                p_rec.permission_granted = level;
            });
        } else {
            //requesting app already has record for user. Update its user perms
            perms.modify(itr, _self /*payer*/, [&](auto &p_rec) {
                p_rec.permission_granted = level;
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
