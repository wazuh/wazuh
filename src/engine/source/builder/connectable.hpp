#ifndef _CONNECTABLE_H
#define _CONNECTABLE_H

#include "rxcpp/rx.hpp"
#include <string>

namespace builder
{

/**
 * @brief a connectable has the property of being able to be connected
 * with another connectable. A connectable does not know its childs, and only
 * knows about the name of the parents it should be connected to.
 *
 * @tparam T the type of the event which will flow between connected connectables
 */
template <class T> class Connectable
{
private:
    std::string m_name;
    std::vector<std::string> m_parents;

    rxcpp::subjects::subject<T> m_subj;
    rxcpp::observable<T> m_obs;

public:
    /**
     * @brief Construct a new Connectable object
     *
     * @param name unique id of the conectable
     */
    Connectable(std::string name) : m_name(name), m_obs(m_subj.get_observable())
    {
    }

    /**
     * @brief connects the ouput of this connectable to the input
     * og the other connectable. This does not check against
     * loops.
     *
     * @param other connectable to send our output
     */
    void connect(const Connectable<T> & other)
    {
        this->output().subscribe(other.input());
    }

    void connect(const std::shared_ptr<Connectable<T>> & other)
    {
        this->output().subscribe(other->input());
    }

    /**
     * @brief set the observable of this connectable. Used to
     * apply observers to this connectable oobservable.
     *
     * @param obs
     */
    void set(rxcpp::observer<T> obs)
    {
        this->m_obs = obs;
    }

    /**
     * @brief return our subscriber, which will receive the events we want
     *
     * @return rxcpp::subscriber<T> our subscriber
     */

    auto input()
    {
        return this->m_subj.get_subscriber();
    }
    /**
     * @brief returns our observable, to whom other will connect to receive
     * the events we have processed.
     *
     * @return rxcpp::observable<T> our observable
     */
    auto output()
    {
        return this->m_obs;
    }

    /**
     * @brief return the list of our parents
     *
     * @return std::vector<std::string>
     */
    auto parents()
    {
        return this->m_parents;
    }

    /**
     * @brief returns our name
     *
     * @return std::string
     */
    auto name() const
    {
        return this->m_name;
    }
};

} // namespace builder
#endif // _CONNECTABLE_H
