/**
 *  @file unification_acl.hpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include <regex>
#include <eosiolib/eosio.hpp>

namespace UnificationFoundation {
    using namespace eosio;

    class unification_uapp : public eosio::contract {
    public:
        explicit unification_uapp(action_name self);

        //@abi action
        void grant(account_name user_account, account_name requesting_app);

        //@abi action
        void revoke(account_name user_account, account_name requesting_app);

        //@abi action
        void addschema(std::string schema, uint8_t schema_vers, uint8_t schedule, uint8_t min_und);

        //@abi action
        void editschema(uint64_t pkey, std::string schema, uint8_t schema_vers, uint8_t schedule, uint8_t min_und);

        //@abi action
        void initreq(uint64_t source_name, uint64_t schema_id, uint8_t req_type, std::string query, uint8_t user_und);

        //@abi action
        void updatereq(uint64_t pkey, std::string hash, std::string aggr);

    private:

        void set_permission(account_name user_account, account_name requesting_app, int permission);

        //@abi table permrecords i64
        struct permrecords {
            uint64_t user_account; //user account ID
            uint8_t permission_granted; //whether or not user has granted access.
            //https://github.com/EOSIO/eos/blob/15953cc1be7a4d4ff168d0235dbaba9464033b70/libraries/chain/contracts/abi_serializer.cpp#L56

            uint64_t primary_key() const { return user_account; }

            EOSLIB_SERIALIZE(permrecords, (user_account)(permission_granted))

        };

        //https://github.com/EOSIO/eos/wiki/Persistence-API#multi-index-constructor
        //eosio::multi_index<N([name_match_abi]), [name_match_struct]> [anything];
        typedef eosio::multi_index<N(permrecords), permrecords> unifperms;

        //@abi table dataschemas i64
        struct dataschemas {
            uint64_t pkey;
            std::string schema; //IPFS Hash etc.
            uint8_t schema_vers; //0 = dev, 1 = prod
            uint8_t schedule; //1 = daily, 2 = weekly, 3 = monthly
            uint8_t min_und;

            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(dataschemas, (pkey)(schema)(schema_vers)(schedule)(min_und))
        };

        typedef eosio::multi_index<N(dataschemas), dataschemas> unifschemas;

        //@abi table datareqs i64
        struct datareqs {
            uint64_t pkey;
            uint64_t source_name; //account name of provider's UApp smart contract
            uint64_t schema_id; //fkey link to provider's schema
            uint8_t req_type; //0 = scheduled, 1 = ad-hoc
            std::string query;
            uint8_t provider_und;
            uint8_t user_und;
            std::string hash;
            std::string aggr;


            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(datareqs, (pkey)(source_name)(schema_id)(req_type)(query)(provider_und)(user_und)(hash)(aggr))
        };

        typedef eosio::multi_index<N(datareqs), datareqs> unifreqs;


    };

    EOSIO_ABI(unification_uapp, (grant)(revoke)(addschema)(editschema)(initreq)(updatereq))
}
