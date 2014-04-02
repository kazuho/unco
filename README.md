Unco - undo commands
====

Note: !!!unco is still in early stage of development and users should be aware of the possibility of data corruption!!!

Unco is a wrapper program that records the changes made to files by programs so that they can be undone laterwards.

Installation
----

```
cmake .
make
make install
```

Running
----

To record a command:

```
% unco record cmd args...
```

To display the list of commands being recorded:

```
% unco history
```

To undo the changes made by one of the commands:

```
% unco undo <index>
```

To redo the undone change:

```
% unco redo <index>
```
