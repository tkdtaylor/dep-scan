/// Edit distance engine for typosquatting detection.
///
/// Implements Levenshtein distance from scratch (no external crate) and provides
/// helpers for normalizing package names and finding closest matches in a list
/// of popular packages.
use std::cmp;

/// Compute the raw Levenshtein distance between two strings.
///
/// This is the minimum number of single-character edits (insertions, deletions,
/// or substitutions) required to transform one string into the other.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Use a single-row optimization: only keep the previous row.
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0usize; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr_row[j] = cmp::min(
                cmp::min(
                    prev_row[j] + 1,     // deletion
                    curr_row[j - 1] + 1, // insertion
                ),
                prev_row[j - 1] + cost, // substitution
            );
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

/// Compute normalized Levenshtein distance between two strings.
///
/// Returns a value between 0.0 (identical) and 1.0 (completely different).
/// Normalized by dividing the raw distance by `max(len(a), len(b))`.
/// Two empty strings are considered identical (distance 0.0).
pub fn normalized_levenshtein(a: &str, b: &str) -> f64 {
    let a_len = a.chars().count();
    let b_len = b.chars().count();
    let max_len = cmp::max(a_len, b_len);

    if max_len == 0 {
        return 0.0;
    }

    let raw = levenshtein(a, b);
    raw as f64 / max_len as f64
}

/// Strip common package name affixes before comparison.
///
/// Removes ecosystem-specific suffixes and prefixes that are commonly added
/// to package names and would cause false-positive typosquatting matches.
///
/// Strips: `-js`, `-node`, `.js`, `-py`, `-python`, `python-`, `py-`
pub fn normalize_package_name(name: &str) -> String {
    let mut result = name.to_lowercase();

    // Strip suffixes (order matters: try longer suffixes first)
    let suffixes = ["-python", "-node", ".js", "-js", "-py"];
    for suffix in &suffixes {
        if let Some(stripped) = result.strip_suffix(suffix) {
            result = stripped.to_string();
            break;
        }
    }

    // Strip prefixes (order matters: try longer prefixes first)
    let prefixes = ["python-", "py-"];
    for prefix in &prefixes {
        if let Some(stripped) = result.strip_prefix(prefix) {
            result = stripped.to_string();
            break;
        }
    }

    result
}

/// Find the closest popular package to a given name, if within threshold.
///
/// Compares the normalized form of `name` against the normalized forms of
/// all packages in `popular_packages`. Returns the best match (original name,
/// distance) if the distance is within `threshold`.
pub fn find_closest_match(
    name: &str,
    popular_packages: &[&str],
    threshold: f64,
) -> Option<(String, f64)> {
    let normalized_name = normalize_package_name(name);
    let mut best: Option<(String, f64)> = None;

    for &pkg in popular_packages {
        let normalized_pkg = normalize_package_name(pkg);
        let dist = normalized_levenshtein(&normalized_name, &normalized_pkg);

        if dist <= threshold {
            match &best {
                Some((_, best_dist)) if dist < *best_dist => {
                    best = Some((pkg.to_string(), dist));
                }
                None => {
                    best = Some((pkg.to_string(), dist));
                }
                _ => {}
            }
        }
    }

    best
}

// ---------------------------------------------------------------------------
// Popular package lists — embedded in binary
// ---------------------------------------------------------------------------

/// Top ~150 most downloaded npm packages that attackers commonly typosquat.
pub const POPULAR_NPM: &[&str] = &[
    "lodash",
    "chalk",
    "react",
    "express",
    "commander",
    "debug",
    "request",
    "async",
    "bluebird",
    "underscore",
    "minimist",
    "glob",
    "mkdirp",
    "uuid",
    "semver",
    "yargs",
    "inquirer",
    "dotenv",
    "cors",
    "axios",
    "moment",
    "webpack",
    "babel-core",
    "typescript",
    "eslint",
    "mocha",
    "jest",
    "prettier",
    "next",
    "vue",
    "angular",
    "rxjs",
    "socket.io",
    "mongoose",
    "mysql",
    "pg",
    "redis",
    "passport",
    "jsonwebtoken",
    "bcrypt",
    "helmet",
    "morgan",
    "body-parser",
    "cookie-parser",
    "multer",
    "nodemon",
    "pm2",
    "aws-sdk",
    "firebase",
    "graphql",
    "apollo-server",
    "sequelize",
    "knex",
    "typeorm",
    "prisma",
    "puppeteer",
    "cheerio",
    "sharp",
    "jimp",
    "nodemailer",
    "handlebars",
    "ejs",
    "pug",
    "sass",
    "less",
    "postcss",
    "autoprefixer",
    "tailwindcss",
    "bootstrap",
    "jquery",
    "d3",
    "three",
    "chart.js",
    "leaflet",
    "mapbox-gl",
    "electron",
    "nw",
    "fs-extra",
    "rimraf",
    "shelljs",
    "cross-env",
    "concurrently",
    "lerna",
    "turbo",
    "nx",
    "rollup",
    "parcel",
    "esbuild",
    "vite",
    "gulp",
    "grunt",
    "coffeescript",
    "babel-loader",
    "ts-node",
    "tslib",
    "core-js",
    "regenerator-runtime",
    "prop-types",
    "classnames",
    "styled-components",
    "emotion",
    "material-ui",
    "formik",
    "yup",
    "joi",
    "ajv",
    "zod",
    "immer",
    "redux",
    "mobx",
    "zustand",
    "recoil",
    "swr",
    "react-query",
    "react-router",
    "react-dom",
    "react-redux",
    "react-hook-form",
    "react-spring",
    "framer-motion",
    "gsap",
    "anime",
    "ramda",
    "fp-ts",
    "date-fns",
    "luxon",
    "dayjs",
    "validator",
    "nanoid",
    "shortid",
    "cuid",
    "color",
    "chroma-js",
    "winston",
    "pino",
    "bunyan",
    "log4js",
    "http-proxy",
    "http-proxy-middleware",
    "compression",
    "serve-static",
    "connect",
    "koa",
    "fastify",
    "hapi",
    "restify",
    "micro",
    "polka",
    "got",
    "node-fetch",
    "superagent",
    "needle",
    "qs",
    "form-data",
    "formidable",
    "busboy",
];

/// Top ~150 most downloaded PyPI packages that attackers commonly typosquat.
pub const POPULAR_PYPI: &[&str] = &[
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "boto3",
    "setuptools",
    "pip",
    "wheel",
    "six",
    "urllib3",
    "certifi",
    "pyyaml",
    "pillow",
    "pytest",
    "scipy",
    "matplotlib",
    "cryptography",
    "jinja2",
    "sqlalchemy",
    "click",
    "pydantic",
    "fastapi",
    "uvicorn",
    "gunicorn",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "mysqlclient",
    "aiohttp",
    "httpx",
    "beautifulsoup4",
    "lxml",
    "scrapy",
    "selenium",
    "playwright",
    "paramiko",
    "fabric",
    "ansible",
    "terraform",
    "docker",
    "kubernetes",
    "awscli",
    "google-cloud-storage",
    "azure-storage-blob",
    "tqdm",
    "rich",
    "colorama",
    "black",
    "flake8",
    "mypy",
    "pylint",
    "isort",
    "autopep8",
    "yapf",
    "bandit",
    "coverage",
    "tox",
    "nox",
    "sphinx",
    "mkdocs",
    "twine",
    "build",
    "flit",
    "poetry",
    "pipenv",
    "virtualenv",
    "pyinstaller",
    "cx-freeze",
    "nuitka",
    "cython",
    "cffi",
    "pycparser",
    "attrs",
    "dataclasses",
    "typing-extensions",
    "importlib-metadata",
    "packaging",
    "toml",
    "tomli",
    "configparser",
    "python-dotenv",
    "decouple",
    "environs",
    "loguru",
    "structlog",
    "sentry-sdk",
    "newrelic",
    "prometheus-client",
    "statsd",
    "scikit-learn",
    "tensorflow",
    "pytorch",
    "keras",
    "xgboost",
    "lightgbm",
    "catboost",
    "transformers",
    "tokenizers",
    "spacy",
    "nltk",
    "gensim",
    "opencv-python",
    "imageio",
    "scikit-image",
    "networkx",
    "igraph",
    "sympy",
    "statsmodels",
    "seaborn",
    "plotly",
    "bokeh",
    "dash",
    "streamlit",
    "gradio",
    "jupyter",
    "notebook",
    "ipython",
    "nbconvert",
    "arrow",
    "pendulum",
    "dateutil",
    "pytz",
    "babel",
    "marshmallow",
    "cattrs",
    "orjson",
    "ujson",
    "msgpack",
    "protobuf",
    "grpcio",
    "graphene",
    "strawberry-graphql",
    "channels",
    "websockets",
    "trio",
    "anyio",
    "starlette",
    "sanic",
    "tornado",
    "twisted",
    "gevent",
    "greenlet",
    "httptools",
    "python-multipart",
    "itsdangerous",
    "werkzeug",
    "markupsafe",
    "mako",
    "chameleon",
    "regex",
    "chardet",
    "charset-normalizer",
];

#[cfg(test)]
mod tests {
    use super::*;

    // T-013-01: Identical strings have distance 0
    #[test]
    fn identical_strings_distance_zero() {
        assert!((normalized_levenshtein("lodash", "lodash") - 0.0).abs() < f64::EPSILON);
    }

    // T-013-02: Single character difference
    #[test]
    fn single_char_difference() {
        let dist = normalized_levenshtein("lodash", "lodas");
        // raw distance = 1 (delete 'h'), max len = 6, normalized = 1/6 ~ 0.167
        assert!(dist > 0.0, "Distance should be > 0");
        assert!(dist < 0.3, "Distance should be small, got {dist}");
        let expected = 1.0 / 6.0;
        assert!(
            (dist - expected).abs() < 0.01,
            "Expected ~{expected}, got {dist}"
        );
    }

    // T-013-03: Transposition detected
    #[test]
    fn transposition_detected() {
        let dist = normalized_levenshtein("lodash", "loadsh");
        // "lodash" vs "loadsh": l-o-d-a-s-h vs l-o-a-d-s-h
        // Positions 2,3 swapped (d,a -> a,d) = 2 substitutions
        // raw distance = 2, max len = 6, normalized = 2/6 ~ 0.333
        assert!(dist > 0.0);
        assert!(dist < 0.5, "Distance should be moderate, got {dist}");
    }

    // T-013-04: Completely different strings have high distance
    #[test]
    fn completely_different_strings_high_distance() {
        let dist = normalized_levenshtein("lodash", "express");
        assert!(dist > 0.7, "Distance should be high, got {dist}");
    }

    // T-013-05: Affix normalization
    #[test]
    fn affix_normalization() {
        assert_eq!(normalize_package_name("lodash-js"), "lodash");
        assert_eq!(normalize_package_name("lodash-node"), "lodash");
        assert_eq!(normalize_package_name("python-requests"), "requests");
        assert_eq!(normalize_package_name("py-requests"), "requests");
        assert_eq!(normalize_package_name("requests-python"), "requests");
        assert_eq!(normalize_package_name("lodash"), "lodash");
        assert_eq!(normalize_package_name("React.js"), "react");
        assert_eq!(normalize_package_name("flask-py"), "flask");
    }

    // T-013-05b: find_closest_match returns best match within threshold
    #[test]
    fn find_closest_match_returns_best() {
        let popular = &["lodash", "express", "react"];
        let result = find_closest_match("loadsh", popular, 0.5);
        assert!(result.is_some(), "Should find a match for 'loadsh'");
        let (name, dist) = result.unwrap();
        assert_eq!(name, "lodash");
        assert!(dist < 0.5);
    }

    #[test]
    fn find_closest_match_returns_none_when_no_match() {
        let popular = &["lodash", "express"];
        let result = find_closest_match("zzzzzzzzzzz", popular, 0.3);
        assert!(
            result.is_none(),
            "Should not find a match for 'zzzzzzzzzzz'"
        );
    }

    // T-013-05c: Empty strings edge case
    #[test]
    fn empty_strings_edge_cases() {
        assert!((normalized_levenshtein("", "") - 0.0).abs() < f64::EPSILON);
        assert!((normalized_levenshtein("", "abc") - 1.0).abs() < f64::EPSILON);
        assert!((normalized_levenshtein("abc", "") - 1.0).abs() < f64::EPSILON);
    }

    // Verify popular package lists have >= 100 entries each
    #[test]
    fn popular_lists_have_sufficient_entries() {
        assert!(
            POPULAR_NPM.len() >= 100,
            "npm list has {} entries, need >= 100",
            POPULAR_NPM.len()
        );
        assert!(
            POPULAR_PYPI.len() >= 100,
            "pypi list has {} entries, need >= 100",
            POPULAR_PYPI.len()
        );
    }

    // Verify no duplicates in popular lists
    #[test]
    fn popular_lists_have_no_duplicates() {
        let mut npm_set = std::collections::HashSet::new();
        for &pkg in POPULAR_NPM {
            assert!(npm_set.insert(pkg), "Duplicate in npm list: {pkg}");
        }
        let mut pypi_set = std::collections::HashSet::new();
        for &pkg in POPULAR_PYPI {
            assert!(pypi_set.insert(pkg), "Duplicate in pypi list: {pkg}");
        }
    }

    // Raw levenshtein sanity checks
    #[test]
    fn raw_levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("a", "b"), 1);
    }
}
