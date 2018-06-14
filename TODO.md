# TODO

## ssllabs-scan v3.0

At present, ssllabs-scan is a barebones reference client application for SSL Labs APIs. While it correctly implements the basic logic of invoking the APIs and executing many assessments in parallel, it lacks many features that are needed for useful continuous testing of multiple TLS servers. In the next major version, we wish to elevate ssllabs-scan into a more useful full-featured tool.

## Better output for single-server testing

Currently, ssllabs-scan doesn't present test results in a nice way (reporting). It would be nice to do this for both ad-hoc scanning and for saved results (see next section).

## Persistent multi-server testing

A scan is defined via a unique ID and a list of hostnames that should be scanned. The unique ID can be any string, but it is recommended to use IDs that carry some meaning. For example, if you wish to perform monthly scanning, an ID consisting of year and month would be a good choice: "2016-01".

The following is a list of scan operations that should be supported:

* Start new scan (ID, filename)
	* Error if there are any results with the supplied ID in the database
	* There should be an option to restart a scan, in which case existing data is deleted
* Continue scan (ID, filename); continues an existing scan. Skips over servers whose results we already have.
* List scans IDs, possibly with some basic information (e.g., times of first and last test, # of tests)
* Delete scan results (ID); deletes all results associated with one scan. 
* Delete everything; deletes all data from the database.
* Option to save results of an ad-hoc test to the database.

* Options to query stored tests by scan ID, date, server hostname, grade, etc.
* Export raw test results as JSON.
* Export test results as custom-formatted CSV.

## Persistence options

For ssllabs-scan, possibly the most useful database to use would be SQLite, which can be embedded into ssllabs-scan itself, thus requiring least effort to get up and running. The option of being database agnostic is tempting, but the file-oriented nature of SQLite has certain advantages that make it useful to rely on it exclusively.

Raw test results (JSON) should always be stored in full. However, it might also be useful to extract key information into one or more additional tables in order to allow for easier reporting and data mining. For example, there could be tables to represent hosts, normalised test results, and certificates. New versions of ssllabs-scan could change the table structure. Because we'll keep raw results, we should be able to simply recreate the necessary table structure and populate it from the raw data. The previous version could always be kept in case of a bothched upgrade. This is a good example of how SQLite is good to rely on.

# Other Requirements

* To minimise confusion related to mismatched version numbers, the major version of ssllabs-scan should always follow the major version of SSL Labs APIs. 
