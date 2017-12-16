A PowerShell implementation of the Tenable SecurityCenter API, SecurityCenter version 5.x.

---

Usage:

Load the module into an appropriate module directory:

```
$env:PSModulePath += ";$env:USERPROFILE\PoSH\modules"
```

Load the core module:

```
Import-Module sc.api.core -DisableNameChecking
```

Note, this module does not function when the PoSH session is running under constrained language mode.
