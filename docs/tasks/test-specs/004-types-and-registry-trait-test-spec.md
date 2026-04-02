# Test Spec — Task 004: Package metadata types + registry trait

## Unit tests

### T-004-01: PackageMetadata construction with all fields
- Create PackageMetadata with all fields populated
- Expected: all fields accessible and correct

### T-004-02: PackageMetadata with optional fields as None
- Create PackageMetadata with only required fields
- Expected: optional fields are None

### T-004-03: PackageMetadata serialization round-trip
- Serialize PackageMetadata to JSON, deserialize back
- Expected: original == deserialized

### T-004-04: RegistryType display
- Expected: RegistryType::Npm displays as "npm", RegistryType::PyPI displays as "pypi"

### T-004-05: RegistryError variants
- Create each RegistryError variant (NotFound, RateLimited, NetworkError, ParseError)
- Expected: each has a meaningful Display message

### T-004-06: RegistryType from string parsing
- Input: "npm", "pypi", "invalid"
- Expected: Ok(Npm), Ok(PyPI), Err
