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

    void unification_uapp::modifyperm(const account_name& user_account,
                                      const account_name& requesting_app,
                                      const uint8_t& level) {

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

    void unification_uapp::modifypermsg(const account_name& user_account,
                                        const account_name& requesting_app,
                                        const std::string& level,
                                        const checksum256& digest,
                                        const signature& sig,
                                        const public_key& pub) {

        require_auth(_self);

        assert_recover_key( (const checksum256 *)&digest, (char *)&sig, sizeof(sig), (char *)&pub, sizeof(pub) );

//        const char* lv = level.c_str();
//
//        checksum256 calc_hash;
//        sha256( lv, sizeof(lv), &calc_hash );
//
//        eosio_assert( calc_hash == digest, "invalid hash" );

        //TODO: check digest == checksum level

        // code, scope. Scope = requesting app.
        unifperms perms(_self, requesting_app);

        auto itr = perms.find(user_account);
        if (itr == perms.end()) {
            //no record for requesting app exists yet. Create one
            perms.emplace(_self /*payer*/, [&](auto &p_rec) {
                p_rec.user_account = user_account;
                p_rec.permission_granted = std::stoi(level);
            });
        } else {
            //requesting app already has record for user. Update its user perms
            perms.modify(itr, _self /*payer*/, [&](auto &p_rec) {
                p_rec.permission_granted =  std::stoi(level);
            });
        }

    }

    void unification_uapp::addschema(const std::string& schema,
                                     const uint8_t& schema_vers,
                                     const uint8_t& schedule,
                                     const uint8_t& min_und) {
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

    void unification_uapp::editschema(const uint64_t& pkey,
                                      const std::string& schema,
                                      const uint8_t& schema_vers,
                                      const uint8_t& schedule,
                                      const uint8_t& min_und) {

        require_auth(_self);

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema = schema;
            s_rec.schedule = schedule;
            s_rec.schema_vers = schema_vers;
            s_rec.min_und = min_und;
        });

    }

    void unification_uapp::setvers(const uint64_t& pkey,const uint8_t& schema_vers) {
        require_auth(_self);

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema_vers = schema_vers;
        });
    }

    void unification_uapp::setschedule(const uint64_t& pkey,const uint8_t& schedule) {
        require_auth(_self);

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schedule = schedule;
        });
    }

    void unification_uapp::setminund(const uint64_t& pkey,const uint8_t& min_und) {
        require_auth(_self);

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.min_und = min_und;
        });
    }

    void unification_uapp::setschema(const uint64_t& pkey,const std::string& schema) {
        require_auth(_self);

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema = schema;
        });
    }

    void unification_uapp::initreq(const uint64_t& source_name,
                                   const uint64_t& schema_id,
                                   const uint8_t& req_type,
                                   const std::string& query,
                                   const uint8_t& user_und) {



    }

    void unification_uapp::updatereq(const uint64_t& pkey,
                                     const std::string& hash,
                                     const std::string& aggr) {

    }


}
