Workflow
========

Commit and branches
-------------------
* Avoid creating new branches in the main repository, prefer to work on your fork instead.
* Never commit anything to master.
* Always submit a Pull Request instead.

Pull Requests
-------------
* Pull Requests have to be reviewed by at least one other person and get his +1.
* travis-ci will run the tests against a submitted Pull Request, needless to say they should pass.

Tests
-----
Categories
~~~~~~~~~~
They are in ``okupy/tests`` directory, separated in four categories: 

* **Unit tests**: They test units. No http requests are allowed. They usually test models, forms, and custom classes/methods. They use django.test.unittest.
* **Integration tests**: They mostly involve http requests using Client(). Usually they test views. They use django.test.unittest.
* **Functional tests**: They usually test general functionality, as well as javascript. They work on a mocked up environment with no real database or LDAP server. They use selenium.
* **Acceptance tests**: They test general functionality, also with selenium, but run against a real environment. 

Try to submit unit and/or integration tests along with your code.

Running the tests
~~~~~~~~~~~~~~~~~
* The command to run the tests is::

    python manage.py test --settings=okupy.tests.settings

* There is a helper script in ``bin/`` directory:: 

    bin/runtests -s

Coverage report
---------------
* You need to emerge ``dev-python/coverage`` or ``pip install coverage``.
* The command to run the tests then becomes:: 
    
    coverage run manage.py test --settings=okupy.tests.settings

* You need to run the following command then to get the report:: 

    coverage report -m

* Or by using the ``bin/runtests`` script, which will print the coverage report as well::

    bin/runtests -s -c

Flake8 report
~~~~~~~~~~~~~
* You need to ``emerge dev-python/flake8`` or ``pip install flake8``.
* To run `flake8` the command is:: 

    flake8 . --exclude=./okupy/tests/settings.py,./okupy/settings,setup.py

* Using the ``bin/runtests`` script:: 

    bin/runtests -s -f

TDaemon
~~~~~~~
If you're working with TDD_, you could use ``dev-python/tdaemon``, which runs the tests every time a filesystem action is performed under your identity.g.o checked out directory.

* In order to run it, cd to your local identity.g.o dir and run:: 

    tdaemon -t django --custom-args="--settings=okupy.tests.settings

* Using the bin/runtests script:: 

    bin/runtests -s -t

* To trigger a tdaemon test run:: 

    bin/trigger_tdaemon_run

.. _TDD: https://en.wikipedia.org/wiki/Test-driven_development

Settings
--------
We split the settings file in the following modules: 

* **__init__.py**: Settings variables that are generic and static without depending if the environment is production or development.
* **production.py**: Settings variables that are bound to production environment.
* **development.py.sample**: Settings variables that are bound to development environment. They are provided through a sample file, since they could be different between various development environments. 
* **local.py.sample**: Settings variables that need clarification in any environment.

Tests have their own settings file under ``okupy/tests/settings.py``

External services
~~~~~~~~~~~~~~~~~
* travis-ci.org_: Runs the tests after every commit, and against every Pull Request
* coveralls.io_: Gathers statistics about test coverage

.. _travis-ci.org: https://travis-ci.org/
.. _coveralls.io: https://coveralls.io/ 
