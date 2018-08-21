/**
 *  @file unification_acl.hpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include <regex>
#include <eosiolib/eosio.hpp>
//#include <eosiolib/time.hpp>
//#include <eosiolib/asset.hpp>
#include <eosiolib/contract.hpp>
#include <eosiolib/crypto.h>

namespace UnificationFoundation {
    using namespace eosio;

    class unification_uapp : public eosio::contract {
    public:
        explicit unification_uapp(action_name self);

        //@abi action
        void modifyperm(const account_name& user_account,
                        const account_name& requesting_app,
                        const uint8_t& level);

        //@abi action
        void modifypermsg(const account_name& user_account,
                          const account_name& requesting_app,
                          const uint8_t& level,
                          const checksum256& digest,
                          const std::string& sig,
                          const public_key& pub);


        //@abi action
        void addschema(const std::string& schema,
                       const uint8_t& schema_vers,
                       const uint8_t& schedule,
                       const uint8_t& min_und);

        //@abi action
        void editschema(const uint64_t& pkey,
                        const std::string& schema,
                        const uint8_t& schema_vers,
                        const uint8_t& schedule,
                        const uint8_t& min_und);

        //@abi action
        void setvers(const uint64_t& pkey,const uint8_t& schema_vers);

        //@abi action
        void setschedule(const uint64_t& pkey,const uint8_t& schedule);

        //@abi action
        void setminund(const uint64_t& pkey,const uint8_t& min_und);

        //@abi action
        void setschema(const uint64_t& pkey,const std::string& schema);

        //@abi action
        void initreq(const uint64_t& source_name,
                     const uint64_t& schema_id,
                     const uint8_t& req_type,
                     const std::string& query,
                     const uint8_t& user_und);

        //@abi action
        void updatereq(const uint64_t& pkey,
                       const std::string& hash,
                       const std::string& aggr);

    private:

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

    EOSIO_ABI(unification_uapp, (modifyperm)(modifypermsg)(addschema)(editschema)(setvers)(setschedule)(setminund)(setschema)(initreq)(updatereq))
}
