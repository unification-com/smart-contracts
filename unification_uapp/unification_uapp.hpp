/**
 *  @file unification_uapp.hpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include <eosiolib/eosio.hpp>
#include <eosiolib/contract.hpp>
#include <eosiolib/crypto.h>

namespace UnificationFoundation {
    using namespace eosio;

    class unification_uapp : public eosio::contract {
    public:
        explicit unification_uapp(action_name self);

        //@abi action
        void initperm(const account_name& consumer_id);

        //@abi action
        void updateperm(const account_name& consumer_id,
                        const std::string& ipfs_hash,
                        const std::string& merkle_root);

        //@abi action
        void addschema(const std::string& schema,
                       const uint8_t& schema_vers,
                       const uint8_t& schedule,
                       const uint8_t& price_sched,
                       const uint8_t& price_adhoc);

        //@abi action
        void editschema(const uint64_t& pkey,
                        const std::string& schema,
                        const uint8_t& schema_vers,
                        const uint8_t& schedule,
                        const uint8_t& price_sched,
                        const uint8_t& price_adhoc);

        //@abi action
        void setvers(const uint64_t& pkey,const uint8_t& schema_vers);

        //@abi action
        void setschedule(const uint64_t& pkey,const uint8_t& schedule);

        //@abi action
        void setpricesch(const uint64_t& pkey,const uint8_t& price_sched);

        //@abi action
        void setpriceadh(const uint64_t& pkey,const uint8_t& price_adhoc);

        //@abi action
        void setschema(const uint64_t& pkey,const std::string& schema);

        //@abi action
        void initreq(const account_name& provider_name,
                     const uint64_t& schema_id,
                     const uint64_t& ts_created,
                     const uint64_t& ts_updated,
                     const uint8_t& req_type,
                     const std::string& query,
                     const uint8_t& price);

        //@abi action
        void updatereq(const uint64_t& pkey,
                       const account_name& provider_name,
                       const std::string& hash,
                       const uint64_t& ts_updated,
                       const std::string& aggr);

        //@abi action
        void setrsakey(std::string rsa_key);

    private:

        //@abi table userperms i64
        struct userperms {
            uint64_t consumer_id;
            std::string ipfs_hash;
            std::string merkle_root;

            uint64_t primary_key() const { return consumer_id; }

            EOSLIB_SERIALIZE(userperms, (consumer_id)(ipfs_hash)(merkle_root))
        };

        typedef eosio::multi_index<N(userperms), userperms> userperms_t;

        //@abi table dataschemas i64
        struct dataschemas {
            uint64_t pkey;
            std::string schema; //IPFS Hash etc.
            uint8_t schema_vers; //0 = dev, 1 = prod
            uint8_t schedule; //1 = daily, 2 = weekly, 3 = monthly
            uint8_t price_sched;
            uint8_t price_adhoc;

            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(dataschemas, (pkey)(schema)(schema_vers)(schedule)(price_sched)(price_adhoc))
        };

        typedef eosio::multi_index<N(dataschemas), dataschemas> unifschemas;

        //@abi table datareqs i64
        struct datareqs {
            uint64_t pkey;
            uint64_t provider_name; //account name of provider's UApp smart contract
            uint64_t schema_id; //fkey link to provider's schema
            uint64_t ts_created; //Unix timestamp of when a request is made
            uint64_t ts_updated; //Unix timestamp of when a request is updated
            uint8_t req_type; //0 = scheduled, 1 = ad-hoc
            std::string query;
            uint8_t price;
            std::string hash;
            std::string aggr;

            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(datareqs, (pkey)(provider_name)(schema_id)(ts_created)(ts_updated)(req_type)(query)(price)(hash)(aggr))
        };

        typedef eosio::multi_index<N(datareqs), datareqs> unifreqs;

        //@abi table rsapubkey i64
        struct rsapubkey {
            uint64_t pkey;
            std::string rsa_pub_key;

            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(rsapubkey, (pkey)(rsa_pub_key))
        };

        typedef eosio::multi_index<N(rsapubkey), rsapubkey> unifrsakey;

    };

    EOSIO_ABI(unification_uapp, (initperm)(updateperm)(addschema)(editschema)(setvers)(setschedule)(setpricesch)(setpriceadh)(setschema)(initreq)(updatereq)(setrsakey))
}
