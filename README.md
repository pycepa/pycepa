# Module Writing

Modules can be written as either a single file or a python package. A single file module must include a class with the same name as the module name.

## Example.py

```python
from core.Module import Module

class Example(Module):
    def module_load(self):
        # do stuff

    def module_unload(self):
        # do stuff
```

## Example/

If you'd like to structure it as a Python package create a directory with the \_\_init\_\_.py file the same as [Example.py](#example.py), where the class inside is named the same as the directory. Dependencies, other files, etc can all be included here just like a normal package.

## Module Class

The module class provides the following methods:

| Method                                         | Description                                                                                                                      |
| :--------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| module\_load(self)                             | Executed on module load, should load events and bootstrap the module.                                                            | 
| module\_unload(self)                           | Executed on module unload, events are automatically cleaned up but if any other clean up needs done this is where to do it.      |
| register(self, event, function)                | Register an event.                                                                                                               |
| register_first(self, event, function)          | Register an event so that it is executed first, not guaranteed to be first but it will be before everything registered normally. |
| trigger(self, event, \*args, \*\*kwargs)       | Trigger the event immediately.                                                                                                   | 
| trigger_avail(self, event, \*args, \*\*kwargs) | Trigger the event once it is registered (lazy execution of an event).                                                            |
