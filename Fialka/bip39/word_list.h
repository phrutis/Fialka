#ifndef BIP39_WORD_LIST_H
#define BIP39_WORD_LIST_H

#include <vector>
#include <string>

namespace BIP39 {

class word_list {
public:
    using data_type = std::vector<std::string>;
    using const_iterator = typename data_type::const_iterator;
    using iterator = typename data_type::iterator;
    using size_type = typename data_type::size_type;

private:
    data_type _words;

public:
    word_list() = default;

#ifdef __cpp_rvalue_references
    void add(std::string word) {
        _words.emplace_back(std::move(word));
    }
#else
    void add(const std::string& word) {
        _words.push_back(word);
    }
#endif

    std::string to_string() const {
        std::string s;
        for (auto i = 0u; i < _words.size(); ++i) {
            s += _words[i];
            if (i != _words.size() - 1) {
                s += ' ';
            }
        }
        return s;
    }

    size_type size() const { return _words.size(); }
    const_iterator cbegin() const { return _words.cbegin(); }
    const_iterator cend() const { return _words.cend(); }
    const_iterator begin() const { return _words.begin(); }
    const_iterator end() const { return _words.end(); }
    iterator begin() { return _words.begin(); }
    iterator end() { return _words.end(); }
};

inline std::ostream& operator<<(std::ostream& os, const word_list& list) {
    os << list.to_string();
    return os;
}

}

#endif
