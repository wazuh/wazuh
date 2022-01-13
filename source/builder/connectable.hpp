#ifndef _CONNECTABLE_H
#define _CONNECTABLE_H

#include <string>

template <class Input, class Output> class Connectable {
private:
  std::string m_name;
  Input m_input;
  Output m_output;

public:
  Connectable(std::string &name, Input input, Output output)
      : m_name(name), m_input(input), m_output(output) {}
  void connect(const Connectable<Input, Output> &other) {
    this->m_output.subscribe(other.m_input);
  }
  Input input() { return this->m_input; }
  Output output() { return this->m_output; }
  std::string name() const { return this->m_name; }
};
#endif // _CONNECTABLE_H
