#ifndef _EXPRESSION_H
#define _EXPRESSION_H

#include <algorithm>
#include <functional>
#include <memory>
#include <sstream>
#include <vector>

#include <fmt/format.h>

namespace base
{

/**
 * The Formula hierarchy is a description of the graph expression to be built,
 * not the actual expression. That's why the classes don't have any compute
 * methods or combine methods. The expression is built from a Formula graph.
 * Comments on each class describe what should be built, under Description
 * section. Functionality and restrictions of the actual formula class are under
 * Restrictions section.
 *
 * Legend of formula descriptions:
 * -> indicates order of computation
 * --> indicates return of the formula
 * true(formula(Event)) indicates that the result of the formula must be true
 * false(formula(Event)) indicates that the result of the formula must be false
 *
 */

class Formula : public std::enable_shared_from_this<Formula>
{
    /**
     * Description:
     * a Formula describes an element that receives a Event and returns a bool,
    * that is a computation. the formula implementation must ensure that if the
    * result is false, the Event is not modified

    * Restrictions:
    * a Formula has entity, which is a unique identifier for the formula
    * a Formula can only be owned by a shared_ptr, to avoid duplication when
    * the formula is referenced by multiple parent formulas
    */

private:
    /**
     * @brief Function to generate a unique identifier for the formula.
     *
     * @return Identifier for the formula.
     */
    static unsigned int generateId();

protected:
    // Unique identifier for the formula
    unsigned int m_id;
    std::string m_name;
    std::string m_typeName;

    /**
     * @brief Construct a new Formula object
     * Protected constructor to ensure that the formula is owned by a shared_ptr.
     * @param name Name of formula.
     * @param typeName Type of formula.
     */
    Formula(std::string name, std::string typeName);

public:
    /**
     * @brief Get the formula's ptr, using Derived shared_from_this
     *
     * @return std::shared_ptr<Derived>
     */
    template<typename Derived>
    std::shared_ptr<Derived> getPtr()
    {
        static_assert(std::is_base_of_v<Formula, Derived>,
                      "Derived must be a subclass of Formula");
        std::shared_ptr<Derived> ptr =
            std::dynamic_pointer_cast<Derived>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error(
                fmt::format("Engine base expression: Error trying to downcast \"{}\" to "
                            "\"{}\" from a "
                            "formula of type \"{}\".",
                            typeid(Formula).name(),
                            typeid(Derived).name(),
                            typeid(decltype(*shared_from_this())).name()));
        }
        return ptr;
    }

    /**
     * @brief Destroy the Formula object
     */
    virtual ~Formula();

    // Type checkers

    /**
     * @brief Check if this Specific Formula instance is that of Term
     * (Formula::Operation::Term).
     *
     * @return true if expression is type Operation::Term, false otherwise.
     */
    virtual bool isTerm() const;

    /**
     * @brief Check if this Specific Formula instance is that of Operation
     * (Formula::Operation::Operation).
     *
     * @return true if expression is type Operation::Operation, false otherwise.
     */
    virtual bool isOperation() const;

    /**
     * @brief Check if this Specific Formula instance is that of And
     * (Formula::Operation::And).
     *
     * @return true if expression is type Operation::And, false otherwise.
     */
    virtual bool isAnd() const;

    /**
     * @brief Check if this Specific Formula instance is that of Or
     * (Formula::Operation::Or).
     *
     * @return true if expression is type Operation::Or, false otherwise.
     */
    virtual bool isOr() const;
    /**
     * @brief Check if this Specific Formula instance is that of Chain
     * (Formula::Operation::Chain).
     *
     * @return true if expression is type Operation::Chain, false otherwise.
     */
    virtual bool isChain() const;

    /**
     * @brief Check if this Specific Formula instance is that of Implication
     * (Formula::Operation::Implication).
     *
     * @return true if expression is type Operation::Implication, false otherwise.
     */
    virtual bool isImplication() const;

    /**
     * @brief Check if this Specific Formula instance is that of Broadcast
     * (Formula::Operation::Broadcast).
     *
     * @return true if expression is type Operation::Broadcast, false otherwise.
     */
    virtual bool isBroadcast() const;

    // getters

    /**
     * @brief Get the Id of this Specific Formula.
     *
     * @return Id of the Formula.
     */
    unsigned int getId() const;

    /**
     * @brief Get the type name of this Specific Formula.
     *
     * @return Type name of the Formula.
     */
    std::string getTypeName() const;

    /**
     * @brief Get the name of this Specific Formula.
     *
     * @return Name of the Formula.
     */
    std::string getName() const;
};

template<typename T>
class Term : public Formula
{
    /*
    * Description:
    * a term describes a computation implemented by a function bool(Event)
    * --> fn(Event)

    * Restrictions:
    * Stores the function that will be used to compute the term
    */

private:
    T m_fn;

protected:
    /**
     * @brief Construct a new Term object.
     * Protected constructor to ensure that the term is owned by a shared_ptr
     *
     * @param name Name of term
     * @param fn the function that will be used to compute the term
     */
    Term(std::string name, T fn)
        : Formula(name, "Term")
        , m_fn {fn}
    {
    }

public:
    /**
     * @brief Construct a new Term object.
     *
     * @param name Name of the Term
     * @param fn The function that will be used to compute the term
     * @return new std::shared_ptr<Term> created
     */
    [[nodiscard]] static std::shared_ptr<Term> create(std::string name, T fn)
    {
        return std::shared_ptr<Term>(new Term(name, fn));
    }

    /**
     * @brief Destroy the Term object
     *
     */
    virtual ~Term() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Term
     * (Formula::Operation::Term).
     *
     * @return true if expression is type Operation::Term, false otherwise.
     */
    bool isTerm() const override { return true; }

    /**
     * @brief Get the function used to compute the term
     *
     * @return the function that will be used to compute the term
     */
    T getFn() const { return m_fn; }

    /**
     * @brief Set the Function used to compute the term
     * 
     * @param fn 
     */
    void setFn(T fn) { m_fn = fn; }
};

// ----- Operations -----
class Operation : public Formula
{
    /* Description:
    * an Operation describes a combination/computation of formulas with
    * specific compute order

    * Restrictions:
    * operations store pointers to the formulas that will be combined
    */

protected:
    std::vector<std::shared_ptr<Formula>> m_operands;

    /**
     * @brief Construct a new Operation object.
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     * @param name Name of Operation
     * @param nameType name of type of Operation
     * @param operands operation operators
     */
    Operation(std::string name,
              std::string nameType,
              std::vector<std::shared_ptr<Formula>> operands);

public:
    /**
     * @brief Destroy the Operation object
     *
     */
    virtual ~Operation();

    /**
     * @brief Check if this Specific Formula instance is that of Operation
     * (Formula::Operation::Operation).
     *
     * @return true if expression is type Operation::Operation, false otherwise.
     */
    bool isOperation() const override;

    // TODO: check this on rvalue
    /**
     * @brief Get the Operands object.
     *
     * @return the operands of the operation.
     */
    const std::vector<std::shared_ptr<Formula>>& getOperands() const;

    // TODO: check this on rvalue
    /**
     * @brief Get the Operands object.
     *
     * @return the operands of the operation.
     */
    std::vector<std::shared_ptr<Formula>>& getOperands();
};

class Implication : public Operation
{
    /**
    * true(left(Event)) -> right(Event) --> true
    * false(left(Event))               --> false

    * Restrictions:
    * Ensure that m_operands size is 2
    */
public:
    /**
     * @brief Construct a new Implication object.
     *
     * @param name Name of the Implication
     * @param leftOperand left operand of the formula
     * @param rightOperand right operand of the formula
     * @return new implication created
     */
    [[nodiscard]] static std::shared_ptr<Implication>
    create(std::string name,
           std::shared_ptr<Formula> leftOperand,
           std::shared_ptr<Formula> rightOperand);

    /**
     * @brief Destroy the Implication object.
     *
     */
    virtual ~Implication();

    /**
     * @brief Check if this Specific Formula instance is that of Implication
     * (Formula::Operation::Implication).
     *
     * @return true if expression is type Operation::Implication, false otherwise.
     */
    bool isImplication() const override;

protected:
    /**
     * @brief Construct a new Implication object.
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     * @param name name of Implication
     * @param leftOperand left operand of the formula
     * @param rightOperand right operand of the formula
     *
     * @return
     */
    Implication(std::string name,
                std::shared_ptr<Formula> leftOperand,
                std::shared_ptr<Formula> rightOperand);
};

class And : public Operation
{
    /*
    * Description:
    * Describes that all the operands must be true and computed sequentially
    * true(form0(Event)) -> true(form1(Event)) -> true(form2(Event)) -> ... ->
    * true(formN(Event)) --> true

    * If one of the formulas is false, stop computation and the result is false
    * true(form0(Event)) -> true(form1(Event)) -> false(form2(Event)) --> false
    */

public:
    /**
     * @brief Construct a new And operation object.
     *
     * @param name name of And operation
     * @param operands operands of the operation
     * @return new and operation created
     */
    [[nodiscard]] static std::shared_ptr<And>
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands);

    /**
     * @brief Destroy the And object
     */
    virtual ~And();

    /**
     * @brief Check if this Specific Formula instance is that of And
     * (Formula::Operation::And).
     *
     * @return true if expression is type Operation::And, false otherwise.
     */
    bool isAnd() const override;

protected:
    /**
     * @brief Construct a new And object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the and operation
     * @param operands operands of the operation
     */
    And(std::string name, std::vector<std::shared_ptr<Formula>> operands);
};

class Or : public Operation
{
    /*
    * Description:
    * Describes that all the operands must be computed sequentially while the
    * result is false false(form0(Event)) -> false(form1(Event)) ->
    * false(form2(Event)) --> false

    * If one of the formulas is true, stop computation and the result is true
    * false(form0(Event)) -> false(form1(Event)) -> true(form2(Event)) --> true
    */

public:
    /**
     * @brief Construct a new Or operation object.
     *
     * @param name name of Or operation
     * @param operands operands of the operation
     * @return new or operation created
     */
    [[nodiscard]] static std::shared_ptr<Or>
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands);

    /**
     * @brief Destroy the Or object
     */
    virtual ~Or();

    /**
     * @brief Check if this Specific Formula instance is that of Or
     * (Formula::Operation::Or).
     *
     * @return true if expression is type Operation::Or, false otherwise.
     */
    bool isOr() const override;

protected:
    /**
     * @brief Construct a new Or object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the or operation
     * @param operands operands of the operation
     */
    Or(std::string name, std::vector<std::shared_ptr<Formula>> operands);
};

class Chain : public Operation
{
    /*
     * Description:
     * compute each formula sequentally regardless of the result and returns
     * true allways form0(Event) -> form1(Event) -> form2(Event) -> ... ->
     * formN(Event) --> true
     */

public:
    /**
     * @brief Construct a new Chain operation object.
     *
     * @param name name of Chain operation
     * @param operands operands of the operation
     * @return new chain operation created
     */
    [[nodiscard]] static std::shared_ptr<Chain>
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands);

    /**
     * @brief Destroy the Chain object
     */
    virtual ~Chain();

    /**
     * @brief Check if this Specific Formula instance is that of Chain
     * (Formula::Operation::Chain).
     *
     * @return true if expression is type Operation::Chain, false otherwise.
     */
    bool isChain() const override;

protected:
    /**
     * @brief Construct a new Chain object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the chain operation
     * @param operands operands of the operation
     */
    Chain(std::string name, std::vector<std::shared_ptr<Formula>> operands);
};

class Broadcast : public Operation
{
public:
    /**
     * @brief Construct a new Broadcast operation object.
     *
     * @param name name of Broadcast operation
     * @param operands operands of the operation
     * @return new broadcast operation created
     */
    [[nodiscard]] static std::shared_ptr<Broadcast>
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands);

    /**
     * @brief Destroy the Broadcast object
     */
    virtual ~Broadcast();

    /**
     * @brief Check if this Specific Formula instance is that of Broadcast
     * (Formula::Operation::Broadcast).
     *
     * @return true if expression is type Operation::Broadcast, false otherwise.
     */
    bool isBroadcast() const override;

protected:
    /**
     * @brief Construct a new Broadcast object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the broadcast operation
     * @param operands operands of the operation
     */
    Broadcast(std::string name, std::vector<std::shared_ptr<Formula>> operands);
};

using Expression = std::shared_ptr<Formula>;

/**
 * @brief Converts the graph described by an Expression to a .dot format string
 *
 * @param expression expression describing the graph
 * @return the string with the .dot format
 */
std::string toGraphvizStr(Expression expression);

} // namespace base

#endif // _EXPRESSION_H
