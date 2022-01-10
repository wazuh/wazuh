#include <string>
#include <vector>

#include <rxcpp/rx.hpp>

/**
 * @brief Contains operation classes and related functionality.
 *
 */
namespace operation {

/**
 * @brief Base class that represents operations.
 * Can't be instantiated directly.
 *
 * @tparam T class of the object processed by operations.
 */
template <class T> class OperationBase {
protected:
  std::string name;
  std::shared_ptr<rxcpp::subscriber<T>> dest_ptr;

  explicit OperationBase(const std::string &name) : name(name) {}

public:
  /**
   * @brief Callback called when previous operation emits an error.
   *
   * @param eptr Pointer to arbitrary exception.
   */
  void on_error(std::exception_ptr eptr) const { this->dest_ptr->on_error(eptr); }

  /**
   * @brief Calback called when completion emitted.
   *
   */
  void on_completed() const { this->dest_ptr->on_completed(); }
};

/**
 * @brief Class to represent an arbitrary operation.
 * A function of the form T(T) implementing the operation must be provided.
 *
 * @tparam T class of the object processed by operations.
 */
template <class T> class Operation : public OperationBase<T> {
private:
  std::function<T(T)> operation;

public:
  /**
   * @brief Construct a new Operation object.
   *
   * @param name Name of the operation.
   * @param operation Function to be performed on every item emitted.
   */
  Operation(const std::string &name, std::function<T(T)> operation)
      : OperationBase<T>(name), operation(operation) {}

  /**
   * @brief Callback called on item emitted.
   *
   * @param t Item.
   */
  void on_next(T t) const {
    T res;
    try {
      res = this->operation(t);
    } catch (...) {
      std::exception_ptr eptr = std::current_exception();
      this->dest_ptr->on_error(eptr);
      return;
    }
    this->dest_ptr->on_next(res);
  }

  /**
   * @brief Method to allow operation concatenation through lift function.
   *
   * @return auto Lifted function.
   */
  auto to_lift() {
    return [=](rxcpp::subscriber<T> dest) {
      this->dest_ptr = std::make_shared<rxcpp::subscriber<T>>(dest);
      return rxcpp::make_subscriber<T>(dest,
                                       rxcpp::make_observer_dynamic<T>(*this));
    };
  }

  /**
   * @brief Method to allow operation composition with pipe function.
   *
   * @return auto Pipeable function.
   */
  auto to_operator() {
    return [=](rxcpp::observable<T> source) {
      rxcpp::observable<T> ret =
          source | rxcpp::operators::lift<T>(this->to_lift());
      return ret;
    };
  }
};

/**
 * @brief Namespace with operation combinators and related functionality.
 *
 */
namespace combinator {

/**
 * @brief Any combinator. Implements an OR operation of multiple operations.
 *
 * @tparam T Class of the item.
 */
template <class T> class Any : public OperationBase<T> {
private:
  std::vector<Operation<T>> operations;

  /**
   * @brief Method to allow operation concatenation through lift function.
   * Made private as this step is only performed on to_operator() once all
   * operations have been combined.
   *
   * @return auto Lifted function.
   */
  auto to_lift() {
    return [=](rxcpp::subscriber<T> dest) {
      this->dest_ptr = std::make_shared<rxcpp::subscriber<T>>(dest);
      return rxcpp::make_subscriber<T>(dest,
                                       rxcpp::make_observer_dynamic<T>(*this));
    };
  }

public:
  /**
   * @brief Construct a new Any object.
   *
   * @param name Name of this operation.
   * @param operations Vector with all operations to be combined.
   */
  Any(const std::string &name, const std::vector<Operation<T>> &operations)
      : OperationBase<T>(name), operations(operations) {}

  /**
   * @brief Callback called on item emitted.
   *
   * @param t Item.
   */
  void on_next(T t) const { this->dest_ptr->on_next(t); }

  /**
   * @brief Method to allow operation composition with pipe function.
   *
   * @return auto Pipeable function.
   */
  auto to_operator() {
    return [=](rxcpp::observable<T> source) {
      auto repeat_point = (source | rxcpp::operators::flat_map([](T t) {
                             return rxcpp::observable<>::just<T>(t);
                           }));
      auto op_it = this->operations.begin();
      auto current = repeat_point | op_it->to_operator();
      for (op_it++; op_it != this->operations.end(); op_it++) {
        auto alt = repeat_point | op_it->to_operator();
        current = current | rxcpp::operators::on_error_resume_next(
                                [=](std::exception_ptr ptr) { return alt; });
      }

      rxcpp::observable<T> ret =
          current | rxcpp::operators::lift<T>(this->to_lift());

      return ret;
    };
  }
};
} // namespace combinator
} // namespace operation
