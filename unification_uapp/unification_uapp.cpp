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
 *  @defgroup unification_uapp UApp Smart Contract
 *  @brief Defines user controlled access to data, metadata schemas, data requests
 *
 *  @details
 *  Each Provider and Consumer is required to deploy this smart contract.
 *  It is used to store metadata about the data a provider is publishing,
 *  Consumer data requests, and user permission information.
 */

    unification_uapp::unification_uapp(action_name self) : contract(self) {}

    void unification_uapp::initperm(const account_name& consumer_id) {

        require_auth2(consumer_id,N(modreq));

        userperms_t perms(_self, consumer_id);

        auto itr = perms.find(consumer_id);
        if (itr == perms.end()) {
            //consumer pays for permissions storage
            //initialise ipfs_hash and merkle_root with nn byte values
            //to allow provider to update values without needing
            //consumer's auth
            perms.emplace(consumer_id /*payer*/, [&](auto &p_rec) {
                p_rec.consumer_id = consumer_id;
                p_rec.ipfs_hash = "0000000000000000000000000000000000000000000000";
                p_rec.merkle_root = "0000000000000000000000000000000000000000000000000000000000000000";
            });
        }

    }

    void unification_uapp::updateperm(const account_name& consumer_id,
                                      const std::string& ipfs_hash,
                                      const std::string& merkle_root) {

        require_auth(_self);
        userperms_t perms(_self, consumer_id);

        auto itr = perms.find(consumer_id);

        eosio_assert(itr != perms.end(), "Permission relationship not found");

        perms.modify(itr, 0 /*payer doesn't change*/, [&](auto &p_rec) {
            p_rec.ipfs_hash = ipfs_hash;
            p_rec.merkle_root = merkle_root;
        });
    }

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

    void unification_uapp::addschema(const std::string& schema,
                                     const uint8_t& schema_vers,
                                     const uint8_t& schedule,
                                     const uint8_t& price_sched,
                                     const uint8_t& price_adhoc) {
        eosio::print("addschema()");

        eosio_assert((schedule == 1
                      || schedule == 2
                      || schedule == 3), "schedule must 1, 2 or 3 for daily, weekly, monthly");

        eosio_assert((schema_vers == 0
                      || schema_vers == 1), "schema_vers must 0 or 1 for dev, prod");

        require_auth2(_self,N(modschema));

        unifschemas u_schema(_self, _self);

        u_schema.emplace(_self, [&]( auto& s_rec ) {
            s_rec.pkey = u_schema.available_primary_key();
            s_rec.schema = schema;
            s_rec.schedule = schedule;
            s_rec.schema_vers = 0;
            s_rec.price_sched = price_sched;
            s_rec.price_adhoc = price_adhoc;
        });
    }

    void unification_uapp::editschema(const uint64_t& pkey,
                                      const std::string& schema,
                                      const uint8_t& schema_vers,
                                      const uint8_t& schedule,
                                      const uint8_t& price_sched,
                                      const uint8_t& price_adhoc) {

        require_auth2(_self,N(modschema));

        eosio_assert((schedule == 1
                     || schedule == 2
                     || schedule == 3), "schedule must 1, 2 or 3 for daily, weekly, monthly");

        eosio_assert((schema_vers == 0
                      || schema_vers == 1), "schema_vers must 0 or 1 for dev, prod");

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema = schema;
            s_rec.schedule = schedule;
            s_rec.schema_vers = schema_vers;
            s_rec.price_sched = price_sched;
            s_rec.price_adhoc = price_adhoc;
        });

    }

    void unification_uapp::setvers(const uint64_t& pkey,const uint8_t& schema_vers) {

        require_auth2(_self,N(modschema));

        eosio_assert((schema_vers == 0
                      || schema_vers == 1), "schema_vers must 0 or 1 for dev, prod");

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema_vers = schema_vers;
        });
    }

    void unification_uapp::setschedule(const uint64_t& pkey,const uint8_t& schedule) {
        require_auth2(_self,N(modschema));

        eosio_assert((schedule == 1
                     || schedule == 2
                     || schedule == 3), "schedule must 1, 2 or 3 for daily, weekly, monthly");

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schedule = schedule;
        });
    }

    void unification_uapp::setpricesch(const uint64_t& pkey,const uint8_t& price_sched) {
        require_auth2(_self,N(modschema));

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.price_sched = price_sched;
        });
    }

    void unification_uapp::setpriceadh(const uint64_t& pkey,const uint8_t& price_adhoc) {
        require_auth2(_self,N(modschema));

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.price_adhoc = price_adhoc;
        });
    }

    void unification_uapp::setschema(const uint64_t& pkey,const std::string& schema) {
        require_auth2(_self,N(modschema));

        unifschemas u_schema(_self, _self);

        auto itr = u_schema.find(pkey);

        eosio_assert(itr != u_schema.end(), "Schema not found");

        u_schema.modify(itr, _self /*payer*/, [&](auto &s_rec) {
            s_rec.schema = schema;
        });
    }

    void unification_uapp::initreq(const account_name& provider_name,
                                   const uint64_t& schema_id,
                                   const uint64_t& ts_created,
                                   const uint64_t& ts_updated,
                                   const uint8_t& req_type,
                                   const std::string& query,
                                   const uint8_t& price) {

        require_auth2(_self,N(modreq));
        //require_auth(_self);

        unifreqs data_requests(_self, _self);

        data_requests.emplace(_self, [&]( auto& d_rec ) {
            d_rec.pkey = data_requests.available_primary_key();
            d_rec.provider_name = provider_name;
            d_rec.schema_id = schema_id;
            d_rec.ts_created = ts_created;
            d_rec.ts_updated = ts_updated;
            d_rec.req_type = req_type;
            d_rec.query = query;
            d_rec.price = price;
        });

        //Call initperm in provider's smart contract, to init required RAM for permissions storage
        action(
                permission_level(_self, N(modreq)),
                provider_name,
                N(initperm),
                _self
        ).send();

    }

    void unification_uapp::updatereq(const uint64_t& pkey,
                                     const account_name& provider_name,
                                     const std::string& hash,
                                     const uint64_t& ts_updated,
                                     const std::string& aggr) {

        require_auth2(provider_name,N(modreq));

        unifreqs data_requests(_self, _self);

        auto itr = data_requests.find(pkey);

        eosio_assert(itr != data_requests.end(), "Data request not found");

        eosio_assert(itr->provider_name == provider_name, "Calling account and provider_name mismatch");

        data_requests.modify(itr, _self /*payer*/, [&](auto &d_rec) {
            d_rec.hash = hash;
            d_rec.aggr = aggr;
            d_rec.ts_updated = ts_updated;
        });

    }

    void unification_uapp::setrsakey(std::string rsa_key) {

        require_auth2(_self,N(modrsakey));

        unifrsakey _unifrsakey(_self, _self);

        auto itr = _unifrsakey.find(0);

        if(itr == _unifrsakey.end()) {
            _unifrsakey.emplace(_self, [&]( auto& rsa_rec ) {
                rsa_rec.pkey = _unifrsakey.available_primary_key();
                rsa_rec.rsa_pub_key = rsa_key;
            });
        } else {
            _unifrsakey.modify(itr, _self /*payer*/, [&](auto &rsa_rec) {
                rsa_rec.rsa_pub_key = rsa_key;
            });
        }
    }


}
