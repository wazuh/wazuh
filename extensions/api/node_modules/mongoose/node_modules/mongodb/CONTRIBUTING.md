## Contributing to the driver

### Bugfixes

- Before starting to write code, look for existing [tickets](https://github.com/mongodb/node-mongodb-native/issues) or [create one](https://github.com/mongodb/node-mongodb-native/issues/new) for your specific issue. That way you avoid working on something that might not be of interest or that has been addressed already in a different branch.
- Fork the [repo](https://github.com/mongodb/node-mongodb-native) _or_ for small documentation changes, navigate to the source on github and click the [Edit](https://github.com/blog/844-forking-with-the-edit-button) button.
- Follow the general coding style of the rest of the project:
  - 2 space tabs
  - no trailing whitespace
  - comma last
  - inline documentation for new methods, class members, etc
  - 0 space between conditionals/functions, and their parenthesis and curly braces
    - `if(..) {`
    - `for(..) {`
    - `while(..) {`
    - `function(err) {`
- Write tests and make sure they pass (execute `make test` from the cmd line to run the test suite).

### Documentation

To contribute to the [API documentation](http://mongodb.github.com/node-mongodb-native/) just make your changes to the inline documentation of the appropriate [source code](https://github.com/mongodb/node-mongodb-native/tree/master/docs) in the master branch and submit a [pull request](https://help.github.com/articles/using-pull-requests/). You might also use the github [Edit](https://github.com/blog/844-forking-with-the-edit-button) button.

If you'd like to preview your documentation changes, first commit your changes to your local master branch, then execute `make generate_docs`. Make sure you have the python documentation framework sphinx installed `easy_install sphinx`. The docs are generated under `docs/build'. If all looks good, submit a [pull request](https://help.github.com/articles/using-pull-requests/) to the master branch with your changes.