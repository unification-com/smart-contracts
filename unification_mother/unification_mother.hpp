/**
 *  @file unification_mother.hpp
 *  @copyright Paul Hodgson @ Unification Foundation
 */

#include <eosiolib/eosio.hpp>

namespace UnificationFoundation {
    using namespace eosio;

    class unification_mother : public eosio::contract {
    public:
        explicit unification_mother(action_name self);

        //abi action
        void addnew(account_name uapp_contract_acc,
                    std::string ipfs_hash);

        //@abi action
        void validate(account_name uapp_contract_acc);

        //@abi action
        void invalidate(account_name uapp_contract_acc);

    private:

        //@abi table validapps i64
        struct validapps {
            uint64_t uapp_contract_acc;
            std::string ipfs_hash;
            uint8_t is_valid;

            uint64_t primary_key() const { return uapp_contract_acc; }

            EOSLIB_SERIALIZE(validapps, (uapp_contract_acc)(ipfs_hash)(is_valid))
        };

        //https://github.com/EOSIO/eos/wiki/Persistence-API#multi-index-constructor
        typedef eosio::multi_index<N(validapps), validapps> valapps;

        //@abi table binhashes i64
        struct binhashes {
            uint64_t pkey;
            uint64_t vnum;
            std::string vcode;
            uint64_t arch_id;
            std::string bin_hash;

            uint64_t primary_key() const { return pkey; }

            EOSLIB_SERIALIZE(binhashes, (pkey)(vnum)(vcode)(arch_id)(bin_hash))
        };

        typedef eosio::multi_index<N(binhashes), binhashes> bin_hashes;
    };

    EOSIO_ABI(unification_mother, (addnew)(validate)(invalidate))
}