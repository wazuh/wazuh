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
    static unsigned int generateId()
    {
        static unsigned int id = 0;
        return id++;
    }

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
    Formula(std::string name, std::string typeName)
        : m_id {generateId()}
        , m_name {name}
        , m_typeName {typeName}
    {
    }

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
                fmt::format("Error trying to downcast [{}] to [{}], this "
                            "Formula type is [{}]",
                            typeid(Formula).name(),
                            typeid(Derived).name(),
                            typeid(decltype(*shared_from_this())).name()));
        }
        return ptr;
    }

    /**
     * @brief Destroy the Formula object
     */
    virtual ~Formula() = default;

    // Type checkers

    /**
     * @brief Check if this Specific Formula instance is that of Term
     * (Formula::Operation::Term).
     *
     * @return true if expression is type Operation::Term, false otherwise.
     */
    virtual bool isTerm() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of Operation
     * (Formula::Operation::Operation).
     *
     * @return true if expression is type Operation::Operation, false otherwise.
     */
    virtual bool isOperation() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of And
     * (Formula::Operation::And).
     *
     * @return true if expression is type Operation::And, false otherwise.
     */
    virtual bool isAnd() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of Or
     * (Formula::Operation::Or).
     *
     * @return true if expression is type Operation::Or, false otherwise.
     */
    virtual bool isOr() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of Chain
     * (Formula::Operation::Chain).
     *
     * @return true if expression is type Operation::Chain, false otherwise.
     */
    virtual bool isChain() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of Implication
     * (Formula::Operation::Implication).
     *
     * @return true if expression is type Operation::Implication, false otherwise.
     */
    virtual bool isImplication() const
    {
        return false;
    }

    /**
     * @brief Check if this Specific Formula instance is that of Broadcast
     * (Formula::Operation::Broadcast).
     *
     * @return true if expression is type Operation::Broadcast, false otherwise.
     */
    virtual bool isBroadcast() const
    {
        return false;
    }

    // getters

    /**
     * @brief Get the Id of this Specific Formula.
     *
     * @return Id of the Formula.
     */
    unsigned int getId() const
    {
        return m_id;
    }

    /**
     * @brief Get the type name of this Specific Formula.
     *
     * @return Type name of the Formula.
     */
    std::string getTypeName() const
    {
        return m_typeName;
    }

    /**
     * @brief Get the name of this Specific Formula.
     *
     * @return Name of the Formula.
     */
    std::string getName() const
    {
        return m_name;
    }
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
     * @brief
     *
     * @param name
     * @param fn
     * @return std::shared_ptr<Term>
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
    bool isTerm() const override
    {
        return true;
    }

    /**
     * @brief Get the function used to compute the term
     *
     * @return the function that will be used to compute the term
     */
    T getFn() const
    {
        return m_fn;
    }
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
     * @param name name of Operation
     * @param nameType name of type of Operation
     * @param operands operation operators
     */
    Operation(std::string name,
              std::string nameType,
              std::vector<std::shared_ptr<Formula>> operands)
        : Formula(name, nameType)
        , m_operands {operands}
    {
    }

public:
    /**
     * @brief Destroy the Operation object
     *
     */
    virtual ~Operation() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Operation
     * (Formula::Operation::Operation).
     *
     * @return true if expression is type Operation::Operation, false otherwise.
     */
    bool isOperation() const override
    {
        return true;
    }

    // TODO: check this on rvalue
    /**
     * @brief Get the Operands object.
     *
     * @return the operands of the operation.
     */
    const std::vector<std::shared_ptr<Formula>>& getOperands() const
    {
        return m_operands;
    }

    // TODO: check this on rvalue
    /**
     * @brief Get the Operands object.
     *
     * @return the operands of the operation.
     */
    std::vector<std::shared_ptr<Formula>>& getOperands()
    {
        return m_operands;
    }
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
     * @param name of the Implication
     * @param leftOperand left operand of the formula
     * @param rightOperand right operand of the formula
     * @return new implication created
     */
    [[nodiscard]] static std::shared_ptr<Implication>
    create(std::string name,
           std::shared_ptr<Formula> leftOperand,
           std::shared_ptr<Formula> rightOperand)
    {
        return std::shared_ptr<Implication>(
            new Implication {name, leftOperand, rightOperand});
    }

    /**
     * @brief Destroy the Implication object.
     *
     */
    virtual ~Implication() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Implication
     * (Formula::Operation::Implication).
     *
     * @return true if expression is type Operation::Implication, false otherwise.
     */
    bool isImplication() const override
    {
        return true;
    }

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
                std::shared_ptr<Formula> rightOperand)
        : Operation {name, "Implication", {leftOperand, rightOperand}}
    {
    }
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
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands)
    {
        return std::shared_ptr<And>(new And(name, operands));
    }

    /**
     * @brief Destroy the And object
     */
    virtual ~And() = default;

    /**
     * @brief Check if this Specific Formula instance is that of And
     * (Formula::Operation::And).
     *
     * @return true if expression is type Operation::And, false otherwise.
     */
    bool isAnd() const override
    {
        return true;
    }

protected:
    /**
     * @brief Construct a new And object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the and operation
     * @param operands operands of the operation
     */
    And(std::string name, std::vector<std::shared_ptr<Formula>> operands)
        : Operation(name, "And", operands)
    {
    }
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
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands)
    {
        return std::shared_ptr<Or>(new Or(name, operands));
    }

    /**
     * @brief Destroy the Or object
     */
    virtual ~Or() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Or
     * (Formula::Operation::Or).
     *
     * @return true if expression is type Operation::Or, false otherwise.
     */
    bool isOr() const override
    {
        return true;
    }

protected:
    /**
     * @brief Construct a new Or object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the or operation
     * @param operands operands of the operation
     */
    Or(std::string name, std::vector<std::shared_ptr<Formula>> operands)
        : Operation(name, "Or", operands)
    {
    }
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
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands)
    {
        return std::shared_ptr<Chain>(new Chain(name, operands));
    }

    /**
     * @brief Destroy the Chain object
     */
    virtual ~Chain() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Chain
     * (Formula::Operation::Chain).
     *
     * @return true if expression is type Operation::Chain, false otherwise.
     */
    bool isChain() const override
    {
        return true;
    }

protected:
    /**
     * @brief Construct a new Chain object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the chain operation
     * @param operands operands of the operation
     */
    Chain(std::string name, std::vector<std::shared_ptr<Formula>> operands)
        : Operation(name, "Chain", operands)
    {
    }
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
    create(std::string name, std::vector<std::shared_ptr<Formula>> operands)
    {
        return std::shared_ptr<Broadcast>(new Broadcast(name, operands));
    }

    /**
     * @brief Destroy the Broadcast object
     */
    virtual ~Broadcast() = default;

    /**
     * @brief Check if this Specific Formula instance is that of Broadcast
     * (Formula::Operation::Broadcast).
     *
     * @return true if expression is type Operation::Broadcast, false otherwise.
     */
    bool isBroadcast() const override
    {
        return true;
    }

protected:
    /**
     * @brief Construct a new Broadcast object
     * Protected constructor to ensure that the operation is owned by a
     * shared_ptr
     *
     * @param name name of the broadcast operation
     * @param operands operands of the operation
     */
    Broadcast(std::string name, std::vector<std::shared_ptr<Formula>> operands)
        : Operation(name, "Broadcast", operands)
    {
    }
};

using Expression = std::shared_ptr<Formula>;

/**
 * @brief Converts the graph described by an Expression to a .dot format string
 *
 * @param expression expression describing the graph
 * @return the string with the .dot format
 */
static std::string toGraphvizStr(Expression expression)
{
    auto header = R"(
compound=true;
fontname="Helvetica,Arial,sans-serif";
fontsize=12;
node [color="#57abff", fontname="Helvetica,Arial,sans-serif", fontsize=10, fontcolor="white"];
edge [fontname="Helvetica,Arial,sans-serif", fontsize=8];
)";
    auto clusterHeader = R"(
style="rounded,filled";
color="#57abff";
)";

    std::stringstream ss;
    ss << "strict digraph G {" << std::endl << header << std::endl;

    // Erase " from string
    auto eraseQuotes = [](std::string str)
    {
        while (str.find("\"") != std::string::npos)
        {
            str.replace(str.find("\""), 1, "'");
        }

        return str;
    };
    auto visit = [&](Expression current, auto& visitRef) -> void
    {
        ss << "subgraph cluster_" << current->getId() << " {" << std::endl
           << clusterHeader << std::endl;
        ss << "label=\"" << current->getTypeName() << "\";" << std::endl;
        ss << current->getId() << " [label=\"" << eraseQuotes(current->getName()) << " ["
           << current->getId() << "]\"];" << std::endl;
        ss << "}" << std::endl;
        if (current->isOperation())
        {
            auto operation = current->getPtr<Operation>();
            int i = 0;
            for (auto& child : operation->getOperands())
            {
                ss << fmt::format("{} -> {} [ltail=cluster_{} lhead=cluster_{} label={} "
                                  "fontcolor=\"red\"];\n",
                                  current->getId(),
                                  child->getId(),
                                  current->getId(),
                                  child->getId(),
                                  i++);
                visitRef(child, visitRef);
            }
        }
    };
    visit(expression, visit);
    ss << "}\n";
    return ss.str();
}

} // namespace base

#endif // _EXPRESSION_H
