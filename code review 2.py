import ast
import os
import sys
import difflib
import json
import argparse
import subprocess
import logging
from radon.metrics import mi_visit
import autopep8 # For Python code formatting
import time # Import the time module
import matplotlib.pyplot as plt # Import matplotlib for graphing

# Try to import the resource module for memory usage (Unix-specific)
try:
    import resource
    resource_available = True
except ImportError:
    resource_available = False

# Try to import the psutil module for memory usage (Cross-platform)
try:
    import psutil
    psutil_available = True
except ImportError:
    psutil_available = False

# --- Constants ---
# Threshold for detecting duplicate lines using SequenceMatcher
SIMILARITY_THRESHOLD = 0.9
# Encoding to use for reading and writing files
ENCODING = "utf-8"
# File to log errors from external tool execution
ERROR_LOG_FILE = 'error_log.txt'
# Maximum line length for code formatting (PEP 8 standard is 79, but 120 is common)
MAX_LINE_LENGTH = 120

# --- External Tool Paths/Commands (Placeholders) ---
# IMPORTANT: Replace these with the actual paths or commands for your system.
# Consider using environment variables or a configuration file for better portability.
CHECKSTYLE_JAR_PATH = "/path/to/your/tools/checkstyle-10.13.0-all.jar" # e.g., path to checkstyle JAR
CHECKSTYLE_CONFIG = "/path/to/your/tools/google_checks.xml" # Optional: path to a Checkstyle config file
PMD_BIN_PATH = "/path/to/your/pmd-bin-6.55.0/bin/run.sh" # e.g., path to PMD run script
PMD_RULESET = "rulesets/java/quickstart.xml" # Example PMD ruleset
GOOGLE_JAVA_FORMAT_JAR = "/path/to/your/tools/google-java-format-1.17.0-all-deps.jar" # e.g., path to Google Java Format JAR

# --- Configure Logging ---
# Set up basic logging to the error file
logging.basicConfig(filename=ERROR_LOG_FILE, level=logging.ERROR,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# --- Configure stdout for Unicode ---
# Ensure stdout can handle Unicode characters
sys.stdout.reconfigure(encoding='utf-8')


class CodeReviewSystem:
    """Automated code review system for complexity, security, and error detection."""

    def _init_(self, filepath):
        """
        Intializes the CodeReviewSystem with the file path to be reviewed.

        Args:
            filepath (str): Path to the file to be reviewed.
        """
        self.filepath = filepath
        # Store original and fixed code for diffing and reporting
        self.original_code = ""
        self.fixed_code = ""
        # To store which memory module was used for reporting
        self.memory_module_used = None

    def get_current_memory_usage(self):
        """Gets the current process memory usage using available modules."""
        if resource_available:
            try:
                # resource.getrusage returns ru_maxrss in kilobytes on many Unix systems
                self.memory_module_used = 'resource'
                return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            except Exception as e:
                logging.error(f"Error getting RAM usage with resource: {e}")
                self.memory_module_used = None
                return "N/A (Error collecting data with resource)"
        elif psutil_available:
            try:
                # psutil.Process().memory_info().rss is Resident Set Size (non-paged memory) in bytes
                process = psutil.Process(os.getpid())
                self.memory_module_used = 'psutil'
                return process.memory_info().rss # Returns bytes
            except Exception as e:
                logging.error(f"Error getting RAM usage with psutil: {e}")
                self.memory_module_used = None
                return "N/A (Error collecting data with psutil)"
        else:
            self.memory_module_used = None
            return "N/A (Neither resource nor psutil available)"

    def run_review(self):
        """Run all analysis checks and generate reports."""
        results = {}
        start_time = time.time() # Record start time

        # Record initial RAM usage
        initial_ram_usage = self.get_current_memory_usage()
        if self.memory_module_used:
             results[f"ram_usage_initial ({self.memory_module_used})"] = initial_ram_usage
        else:
             results["ram_usage_initial"] = initial_ram_usage


        # Read the file content once at the beginning
        self.original_code = self.read_file(self.filepath)

        # If file reading failed, report and exit
        if not self.original_code:
            print(f"❌ Could not read file: {self.filepath}. Review aborted.")
            return

        language = self.detect_language(self.filepath)

        # Apply formatting first for languages where we modify the file in place or generate fixed code early
        if language == 'python':
             # For Python, apply formatting and get the fixed code string
             self.fixed_code = self.format_python_code(self.original_code)
             # Pass both original and fixed code to analyze_python for complexity comparison
             results.update(self.analyze_python(self.original_code, self.fixed_code))
        elif language == 'javascript':
             # For JS, format in place and then re-read the file
             results["formatting_status"] = self.format_javascript_code()
             self.fixed_code = self.read_file(self.filepath) # Read the file again after formatting
             results.update(self.analyze_javascript())
        elif language == 'html':
             # For HTML, format in place and then re-read the file
             results["formatting_status"] = self.format_html_code()
             self.fixed_code = self.read_file(self.filepath) # Read the file again after formatting
             results.update(self.analyze_html())
        elif language == 'java':
             # For Java, format in place and then re-read the file
             results["formatting_status"] = self.format_java_code()
             self.fixed_code = self.read_file(self.filepath) # Read the file again after formatting
             results.update(self.analyze_java())
        elif language == 'c':
             # For C, format and get the fixed code string
             self.fixed_code = self.format_c_code(self.original_code)
             results["formatting_status"] = "Formatted code generated." if self.fixed_code != self.original_code else "C formatting did not change code."
             results.update(self.analyze_c())
        elif language == 'cpp':
             # For C++, format and get the fixed code string
             self.fixed_code = self.format_cpp_code(self.original_code)
             results["formatting_status"] = "Formatted code generated." if self.fixed_code != self.original_code else "C++ formatting did not change code."
             results.update(self.analyze_cpp())
        else:
            print(f"⚠ Unsupported language for detailed analysis: {language}")
            results["basic_analysis"] = f"Language detected: {language}. No detailed analysis available."
            self.fixed_code = self.original_code # No formatting applied

        analysis_fix_end_time = time.time() # Record time after analysis and fixing
        results["time_analysis_fix"] = analysis_fix_end_time - start_time

        # Record RAM usage after analysis and fixing
        analysis_fix_ram_usage = self.get_current_memory_usage()
        if self.memory_module_used:
             results[f"ram_usage_analysis_fix ({self.memory_module_used})"] = analysis_fix_ram_usage
        else:
             results["ram_usage_analysis_fix"] = analysis_fix_ram_usage


        # Add fix suggestions based on runtime errors (primarily for Python, but can be extended)
        # Note: Runtime errors are still detected on the original file path.
        results["Fix Suggestions"] = self.suggest_fixes(results.get("runtime_errors", ""))

        # Calculate report generation time and RAM usage before printing summary
        report_start_time = time.time() # Record time before saving report
        # Save the detailed results to a JSON file (this is part of report generation)
        self.save_updated_code_report(results, language)
        report_end_time = time.time() # Record time after saving report
        results["time_report_generation"] = report_end_time - report_start_time

        # Record RAM usage after report generation
        report_generation_ram_usage = self.get_current_memory_usage()
        if self.memory_module_used:
             results[f"ram_usage_report_generation ({self.memory_module_used})"] = report_generation_ram_usage
        else:
             results["ram_usage_report_generation"] = report_generation_ram_usage

        # Generate performance graphs
        self.generate_performance_graphs(results)


        # Now generate and print the summary with all metrics available
        self.print_summary(results, language)


    def detect_language(self, filepath):
        """
        Detects the programming language of the file based on its extension.

        Args:
            filepath (str): Path to the file.

        Returns:
            str: The detected language (e.g., 'python', 'javascript', 'html', 'java', 'c', 'cpp') or None if unknown.
        """
        _, ext = os.path.splitext(filepath)
        ext = ext.lower() # Use lowercase extension for consistent matching
        if ext == '.py':
            return 'python'
        elif ext in ['.js', '.jsx']:
            return 'javascript'
        elif ext in ['.html', '.htm']:
            return 'html'
        elif ext == '.java':
            return 'java'
        elif ext == '.c':
            return 'c'
        elif ext in ['.cpp', '.cc', '.cxx', '.h', '.hpp']:
            return 'cpp'
        return 'unknown' # Return 'unknown' instead of None

    def read_file(self, filepath):
        """
        Reads the content of the file.

        Args:
            filepath (str): Path to the file.

        Returns:
            str: The content of the file, or an empty string if an error occurs.
        """
        try:
            with open(filepath, "r", encoding=ENCODING) as f:
                return f.read()
        except FileNotFoundError:
            logging.error(f"File not found: {filepath}")
            print(f"❌ Error: File not found at {filepath}")
            return ""
        except Exception as e:
            logging.error(f"Error reading file: {filepath} - {e}")
            print(f"❌ Error reading file {filepath}: {e}")
            return ""

    # --- Language Specific Analysis Methods ---

    # Modified analyze_python to accept both original and fixed code
    def analyze_python(self, original_code, fixed_code):
        """Analyzes Python code for complexity, duplicates, security, errors, and style."""
        print("🔬 Analyzing Python code...")
        results = {
            # Calculate complexity for both original and fixed code
            "complexity_original": self.analyze_complexity(original_code),
            "complexity_fixed": self.analyze_complexity(fixed_code),
            # Duplicate detection using difflib on the potentially fixed code
            "duplicates": self.detect_duplicates(fixed_code),
            # Security analysis using Bandit (runs on file path)
            "security": self.analyze_security(),
            # Static analysis using Pylint (runs on file path)
            "pylint": self.run_pylint(),
            # Type checking using MyPy (runs on file path)
            "mypy": self.run_mypy(),
            # Style guide enforcement using Flake8 (runs on file path)
            "flake8": self.run_flake8(),
            # Dependency vulnerability check using pip-audit (runs on environment)
            "pip_audit": self.run_pip_audit(),
            # Runtime error detection by executing the script (runs on file path)
            "runtime_errors": self.detect_runtime_errors(),
            # Magic number detection using AST on the potentially fixed code
            "magic_numbers": self.detect_magic_numbers(fixed_code),
        }
        return results

    def analyze_javascript(self):
        """Analyzes JavaScript code."""
        print("🔬 Analyzing JavaScript code...")
        results = {
            # Linting using ESLint (runs on file path)
            "eslint": self.run_eslint(),
            # Formatting status is added in run_review
        }
        return results

    def analyze_html(self):
        """Analyzes HTML code."""
        print("🔬 Analyzing HTML code...")
        results = {
            # Linting using HTMLHint (runs on file path)
            "htmlhint": self.run_htmlhint(),
             # Formatting status is added in run_review
        }
        return results

    def analyze_java(self):
        """Analyzes Java code."""
        print("🔬 Analyzing Java code...")
        results = {
            # Style checking using Checkstyle (runs on file path)
            "checkstyle": self.run_checkstyle(),
            # Static analysis using PMD (runs on file path)
            "pmd": self.run_pmd(),
             # Formatting status is added in run_review
        }
        return results

    def analyze_c(self):
        """Analyzes C code."""
        print("🔬 Analyzing C code...")
        results = {
            # Compiler warnings/syntax check using GCC (runs on file path)
            "gcc": self.run_gcc_analysis(),
            # Static analysis using Cppcheck (runs on file path)
            "cppcheck": self.run_cppcheck(),
             # Formatting status is added in run_review
        }
        return results

    def analyze_cpp(self):
        """Analyzes C++ code."""
        print("🔬 Analyzing C++ code...")
        results = {
            # Compiler warnings/syntax check using G++ (runs on file path)
            "gpp": self.run_gpp_analysis(),
            # Static analysis using Cppcheck (runs on file path)
            "cppcheck": self.run_cppcheck(),
             # Formatting status is added in run_review
        }
        return results

    # --- Formatting Methods ---

    def format_python_code(self, code):
        """Apply basic fixes and use autopep8 for Python formatting."""
        try:
            # Use autopep8 to fix code style issues based on PEP 8
            formatted_code = autopep8.fix_code(code, options={'max_line_length': MAX_LINE_LENGTH})
            return formatted_code
        except Exception as e:
            logging.error(f"Error during autopep8 formatting: {e}")
            print(f"❌ Error during autopep8 formatting: {e}")
            return code # Return original code if formatting fails

    def format_javascript_code(self):
        """Formats JavaScript code using prettier (modifies file in place)."""
        # Note: Prettier modifies the file in place.
        try:
            result = subprocess.run(
                ["prettier", "--write", self.filepath],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                return "✅ Prettier formatting applied."
            else:
                logging.error(f"Prettier formatting issues or errors: {result.stderr}")
                return f"⚠ Prettier formatting issues or errors:\n{result.stderr}"
        except FileNotFoundError:
            logging.error("Prettier is not installed or not in PATH.")
            return "❌ Prettier execution failed: not installed or not in PATH. (Install with: npm install -g prettier)"
        except Exception as e:
            logging.error(f"Prettier execution failed: {e}")
            return f"❌ Prettier execution failed: {e}"

    def format_html_code(self):
        """Formats HTML code using Prettier (modifies file in place)."""
        # Using Prettier for HTML as well, modifies file in place.
        return self.format_javascript_code() # Prettier handles HTML

    def format_java_code(self):
        """Formats Java code using Google Java Format (modifies file in place)."""
        # Note: Google Java Format modifies the file in place.
        if not os.path.exists(GOOGLE_JAVA_FORMAT_JAR):
             logging.error(f"Google Java Format JAR not found at: {GOOGLE_JAVA_FORMAT_JAR}")
             return f"❌ Google Java Format execution failed: JAR not found at {GOOGLE_JAVA_FORMAT_JAR}. (Download from Maven Central)"

        command = ["java", "-jar", GOOGLE_JAVA_FORMAT_JAR, "--replace", self.filepath]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                 return "✅ Google Java Format applied."
            else:
                 logging.error(f"Google Java Format issues or errors: {result.stderr}")
                 return f"⚠ Google Java Format issues or errors:\n{result.stderr}"
        except Exception as e:
            logging.error(f"Google Java Format execution failed: {e}")
            return f"❌ Google Java Format execution failed: {e}"


    def format_c_code(self, code):
        """Formats C code using clang-format (returns formatted code)."""
        # Using clang-format to output formatted code to stdout instead of modifying in place.
        try:
            # Use '-' for stdin and stdout
            result = subprocess.run(
                ["clang-format", "-style=file", "-"], # -style=file looks for .clang-format file
                capture_output=True, text=True, input=code, check=False
            )
            if result.returncode == 0:
                return result.stdout # Return the formatted code
            else:
                logging.error(f"clang-format issues or errors: {result.stderr}")
                print(f"⚠ clang-format issues or errors:\n{result.stderr}")
                return code # Return original code if formatting fails
        except FileNotFoundError:
            logging.error("clang-format not found. Please ensure it's installed and in your PATH.")
            print("❌ clang-format execution failed: not found. (Install clang-format)")
            return code
        except Exception as e:
            logging.error(f"clang-format execution failed: {e}")
            print(f"❌ clang-format execution failed: {e}")
            return code

    def format_cpp_code(self, code):
        """Formats C++ code using clang-format (returns formatted code)."""
        # Using the same formatter for C++ as C, returning formatted code.
        return self.format_c_code(code)

    # --- Static Analysis / Linting Methods ---

    def run_eslint(self):
        """Runs ESLint on the JavaScript file."""
        try:
            # --no-error-on-unmatched-pattern prevents errors if no files match pattern (though we pass a specific file)
            # --format compact provides a concise output
            result = subprocess.run(
                ["eslint", "--no-error-on-unmatched-pattern", "--format", "compact", self.filepath],
                capture_output=True, text=True, check=False
            )
            # ESLint returns 0 for no errors, non-zero for errors or issues.
            # We capture stdout regardless of return code to show issues.
            return result.stdout if result.stdout.strip() else "✅ ESLint: No issues found."
        except FileNotFoundError:
            logging.error("ESLint is not installed or not in PATH.")
            return "❌ ESLint execution failed: not installed or not in PATH. (Install with: npm install -g eslint)"
        except Exception as e:
            logging.error(f"ESLint execution failed: {e}")
            return f"❌ ESLint execution failed: {e}"

    def run_htmlhint(self):
        """Runs HTMLHint on the HTML file."""
        try:
            # --format compact provides a concise output
            result = subprocess.run(
                ["htmlhint", "--format", "compact", self.filepath],
                capture_output=True, text=True, check=False
            )
            # HTMLHint returns 0 for no errors, non-zero for errors.
            # We capture stdout regardless of return code to show issues.
            return result.stdout if result.stdout.strip() else "✅ HTMLHint: No issues found."
        except FileNotFoundError:
            logging.error("HTMLHint is not installed or not in PATH.")
            return "❌ HTMLHint execution failed: not installed or not in PATH. (Install with: npm install -g htmlhint)"
        except Exception as e:
            logging.error(f"HTMLHint execution failed: {e}")
            return f"❌ HTMLHint execution failed: {e}"

    def run_checkstyle(self):
        """Runs Checkstyle on the Java file."""
        # Note: This requires the Checkstyle JAR and optionally a configuration file.
        if not os.path.exists(CHECKSTYLE_JAR_PATH):
             logging.error(f"Checkstyle JAR not found at: {CHECKSTYLE_JAR_PATH}")
             return f"❌ Checkstyle execution failed: JAR not found at {CHECKSTYLE_JAR_PATH}. (Download Checkstyle JAR)"

        command = ["java", "-jar", CHECKSTYLE_JAR_PATH]
        if CHECKSTYLE_CONFIG and os.path.exists(CHECKSTYLE_CONFIG):
            command.extend(["-c", CHECKSTYLE_CONFIG])
        command.append(self.filepath)

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
             # Checkstyle outputs issues to stdout or stderr depending on configuration/version.
             # We'll capture both and combine.
            output = (result.stdout + result.stderr).strip()
            return output if output else "✅ Checkstyle: No issues found."
        except Exception as e:
            logging.error(f"Checkstyle execution failed: {e}")
            return f"❌ Checkstyle execution failed: {e}"

    def run_pmd(self):
        """Runs PMD on the Java file."""
        # Note: This requires the PMD binary and a ruleset.
        if not os.path.exists(PMD_BIN_PATH):
             logging.error(f"PMD run script not found at: {PMD_BIN_PATH}")
             return f"❌ PMD execution failed: run script not found at {PMD_BIN_PATH}. (Install PMD)"

        command = [PMD_BIN_PATH, "-d", self.filepath, "-f", "text", "-R", PMD_RULESET]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            # PMD outputs issues to stdout.
            return result.stdout if result.stdout.strip() else "✅ PMD: No issues found."
        except Exception as e:
            logging.error(f"PMD execution failed: {e}")
            return f"❌ PMD execution failed: {e}"

    def run_gcc_analysis(self):
        """Runs GCC analysis on the C file (syntax check and warnings)."""
        # -Wall and -Wextra enable extensive warnings. -fsyntax-only checks syntax without compiling.
        try:
            result = subprocess.run(
                ["gcc", "-Wall", "-Wextra", "-fsyntax-only", self.filepath],
                capture_output=True, text=True, check=False
            )
            # GCC outputs warnings/errors to stderr.
            return result.stderr if result.stderr.strip() else "✅ GCC: No syntax errors or warnings."
        except FileNotFoundError:
            logging.error("GCC not found. Please ensure it's installed and in your PATH.")
            return "❌ GCC execution failed: not found. (Install GCC)"
        except Exception as e:
            logging.error(f"GCC execution failed: {e}")
            return f"❌ GCC execution failed: {e}"

    def run_gpp_analysis(self):
        """Runs G++ analysis on the C++ file (syntax check and warnings)."""
        # -Wall and -Wextra enable extensive warnings. -std=c++17 sets C++ standard. -fsyntax-only checks syntax.
        try:
            result = subprocess.run(
                ["g++", "-Wall", "-Wextra", "-std=c++17", "-fsyntax-only", self.filepath],
                capture_output=True, text=True, check=False
            )
            # G++ outputs warnings/errors to stderr.
            return result.stderr if result.stderr.strip() else "✅ G++: No syntax errors or warnings."
        except FileNotFoundError:
            logging.error("G++ not found. Please ensure it's installed and in your PATH.")
            return "❌ G++ execution failed: not found. (Install G++)"
        except Exception as e:
            logging.error(f"G++ execution failed: {e}")
            return f"❌ G++ execution failed: {e}"

    def run_cppcheck(self):
        """Runs Cppcheck on the C/C++ file."""
        # --enable=all enables all checks.
        try:
            result = subprocess.run(
                ["cppcheck", "--enable=all", self.filepath],
                capture_output=True, text=True, check=False
            )
            # Cppcheck outputs issues to stderr.
            return result.stderr if result.stderr.strip() else "✅ Cppcheck: No issues found."
        except FileNotFoundError:
            logging.error("Cppcheck not found. Please ensure it's installed and in your PATH.")
            return "❌ Cppcheck execution failed: not found. (Install Cppcheck)"
        except Exception as e:
            logging.error(f"Cppcheck execution failed: {e}")
            return f"❌ Cppcheck execution failed: {e}"

    def run_pylint(self):
        """Runs Pylint on the Python file."""
        try:
            # --max-line-length aligns with the constant
            pylint_output = subprocess.run(
                ["pylint", "--max-line-length", str(MAX_LINE_LENGTH), self.filepath],
                capture_output=True, text=True, check=False
            )
            # Pylint outputs to stdout.
            return pylint_output.stdout
        except FileNotFoundError:
            logging.error("Pylint is not installed or not in PATH.")
            return "❌ Pylint execution failed: not installed or not in PATH. (Install with: pip install pylint)"
        except Exception as e:
            logging.error(f"Pylint execution failed: {e}")
            return f"❌ Pylint execution failed: {e}"

    def run_mypy(self):
        """Runs MyPy on the Python file."""
        try:
            # --ignore-missing-imports can be useful if not all dependencies are installed
            mypy_output = subprocess.run(
                ["mypy", "--ignore-missing-imports", self.filepath],
                capture_output=True, text=True, check=False
            )
            # MyPy outputs to stdout.
            return mypy_output.stdout
        except FileNotFoundError:
            logging.error("MyPy is not installed or not in PATH.")
            return "❌ MyPy execution failed: not installed or not in PATH. (Install with: pip install mypy)"
        except Exception as e:
            logging.error(f"MyPy execution failed: {e}")
            return f"❌ MyPy execution failed: {e}"

    def run_flake8(self):
        """Runs Flake8 on the Python file."""
        try:
            # --max-line-length aligns with the constant
            flake8_output = subprocess.run(
                ["flake8", "--max-line-length", str(MAX_LINE_LENGTH), self.filepath],
                capture_output=True, text=True, check=False
            )
            # Flake8 outputs to stdout.
            return flake8_output.stdout
        except FileNotFoundError:
            logging.error("Flake8 is not installed or not in PATH.")
            return "❌ Flake8 execution failed: not installed or not in PATH. (Install with: pip install flake8)"
        except Exception as e:
            logging.error(f"Flake8 execution failed: {e}")
            return f"❌ Flake8 execution failed: {e}"

    def run_pip_audit(self):
        """Runs pip-audit to check for vulnerable dependencies."""
        # Note: This checks the environment's installed packages, not just those required by the file.
        try:
            # check=True here because a non-zero exit code indicates vulnerabilities found, which is not an execution error.
            # We want to capture the output in this case.
            result = subprocess.run(
                ["pip-audit"],
                capture_output=True, text=True, check=True
            )
            # pip-audit outputs results to stdout.
            return result.stdout if result.stdout.strip() else "✅ Pip-audit: No known vulnerabilities found in installed packages."
        except FileNotFoundError:
            logging.error("Pip-audit is not installed or not in PATH.")
            return "❌ Pip-audit execution failed: not installed or not in PATH. (Install with: pip install pip-audit)"
        except subprocess.CalledProcessError as e:
             # This block catches non-zero exit codes from pip-audit when vulnerabilities are found.
             logging.warning(f"Pip-audit found vulnerabilities: {e.stderr}")
             return f"⚠ Pip-audit found vulnerabilities:\n{e.stdout + e.stderr}"
        except Exception as e:
            logging.error(f"Error running Pip-audit: {e}")
            return f"❌ Error running Pip-audit: {e}"

    # --- Analysis Helper Methods ---

    # analyze_complexity now returns a formatted string based on the result type
    def analyze_complexity(self, code):
        """Analyzes the code complexity using Radon."""
        try:
            # mi_visit returns a list of Maintainability Index results when multi=True
            # or a single float when multi=False (or perhaps in other cases)
            maintainability_results = mi_visit(code, multi=True)

            if isinstance(maintainability_results, list):
                # Format the output for readability if it's a list of results
                if maintainability_results:
                    return [f"MI for {item.name}: {item.mi:.2f} ({item.rank})" for item in maintainability_results]
                else:
                    return "No complexity metrics found (possibly empty file or no analyzable blocks)."
            elif isinstance(maintainability_results, float):
                # If it's a single float (e.g., for the whole module), format and return it
                # Radon's MI is typically out of 100
                return f"Overall Maintainability Index: {maintainability_results:.2f}/100"
            else:
                # Handle unexpected return types from mi_visit
                return f"⚠ Unexpected result from complexity analysis: {maintainability_results}"

        except Exception as e:
            # This catch will now trigger if Radon fails to parse the fixed code
            logging.error(f"Error analyzing complexity on potentially fixed code: {e}")
            return f"❌ Error analyzing complexity on potentially fixed code: {e}"

    # detect_duplicates remains the same, operating on the provided code string
    def detect_duplicates(self, code):
        """Detects duplicate code lines using difflib."""
        # Note: This is a simple line-based check and may not find all duplicates.
        # More advanced tools like dupfinder or token-based analysis are more comprehensive.
        try:
            lines = [line.strip() for line in code.splitlines() if line.strip()]
            # Reverting to original pairwise check for better (though slower) detection:
            duplicates = sum(
                 1 for i in range(len(lines)) for j in range(i + 1, len(lines))
                 if difflib.SequenceMatcher(None, lines[i], lines[j]).ratio() > SIMILARITY_THRESHOLD
             )
            return duplicates
        except Exception as e:
            logging.error(f"Error detecting duplicates: {e}")
            return f"❌ Error detecting duplicates: {e}"

    def analyze_security(self):
        """Analyzes the code for security vulnerabilities using Bandit."""
        # Note: Bandit is Python-specific and runs on the file path.
        try:
            # -f json outputs results in JSON format
            # check=True because Bandit's non-zero exit code indicates issues found, not an execution error.
            # We want to capture the output in this case.
            result = subprocess.run(
                ["bandit", self.filepath, "-f", "json"],
                capture_output=True, text=True, check=True
            )
            # Load the JSON output
            security_report = json.loads(result.stdout)
            return security_report
        except FileNotFoundError:
            logging.error("Bandit is not installed or not in PATH.")
            return "❌ Bandit execution failed: not installed or not in PATH. (Install with: pip install bandit)"
        except subprocess.CalledProcessError as e:
             # Bandit exits with non-zero if issues are found. We still want the JSON output.
             try:
                 security_report = json.loads(e.stdout)
                 return security_report
             except json.JSONDecodeError:
                 logging.error(f"Bandit execution failed and output is not valid JSON: {e.stdout + e.stderr}")
                 return f"❌ Bandit execution failed and output is not valid JSON:\n{e.stdout + e.stderr}"
        except json.JSONDecodeError:
             logging.error(f"Bandit output is not valid JSON: {result.stdout}")
             return f"❌ Bandit output is not valid JSON:\n{result.stdout}"
        except Exception as e:
            logging.error(f"Bandit execution failed: {e}")
            return f"❌ Bandit execution failed: {e}"

    def detect_runtime_errors(self):
        """Detects runtime errors by executing the Python script."""
        # Note: This is a basic execution and runs on the original file path.
        # More complex scenarios require dedicated testing.
        try:
            # Run the script and capture output. timeout prevents infinite execution.
            result = subprocess.run(
                ["python", self.filepath],
                capture_output=True, text=True, timeout=10 # Added a timeout
            )
            # If stderr has content, it likely indicates a runtime error.
            return result.stderr if result.stderr else "✅ No obvious runtime errors found during basic execution."
        except FileNotFoundError:
            logging.error(f"Error: Python interpreter not found or file does not exist: {self.filepath}")
            return f"❌ Error: Python interpreter not found or file does not exist: {self.filepath}"
        except subprocess.TimeoutExpired:
             logging.warning(f"Script execution timed out after 10 seconds: {self.filepath}")
             return f"⚠ Script execution timed out after 10 seconds. Possible infinite loop or long execution time."
        except Exception as e:
            logging.error(f"Error executing script: {e}")
            return f"❌ Error executing script: {e}"

    # detect_magic_numbers remains the same, operating on the provided code string
    def detect_magic_numbers(self, code):
        """Detects magic numbers in the Python code using AST."""
        try:
            tree = ast.parse(code)
            # Walk the AST and find Constant nodes that are integers or floats, excluding 0 and 1.
            magic_numbers = [
                node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and node.value not in (0, 1)
            ]
            return len(magic_numbers)
        except Exception as e:
            # This catch will now trigger if AST fails to parse the fixed code
            logging.error(f"Error detecting magic numbers on potentially fixed code: {e}")
            return f"❌ Error detecting magic numbers on potentially fixed code: {e}"

    def suggest_fixes(self, runtime_errors):
        """Suggests fixes for common runtime errors."""
        suggestions = []
        # Add more specific checks and suggestions based on error messages
        if isinstance(runtime_errors, str):
            if "TypeError" in runtime_errors:
                suggestions.append("🔹 Fix TypeError: Ensure variables have matching data types or perform explicit type casting.")
            if "IndexError" in runtime_errors:
                suggestions.append("🔹 Fix IndexError: Check list/sequence boundaries before accessing elements. Use len() or in operator.")
            if "ValueError" in runtime_errors:
                suggestions.append("🔹 Fix ValueError: Validate input values before attempting conversions or operations that expect specific formats.")
            if "UnicodeEncodeError" in runtime_errors or "UnicodeDecodeError" in runtime_errors:
                suggestions.append("🔹 Fix Unicode Error: Ensure consistent encoding (e.g., UTF-8) when reading/writing files or handling strings. Check sys.stdout.reconfigure(encoding='utf-8').")
            if "NameError" in runtime_errors:
                suggestions.append("🔹 Fix NameError: Ensure all variables and functions are defined and spelled correctly before use. Check variable scope.")
            if "FileNotFoundError" in runtime_errors:
                suggestions.append(
                    f"🔹 Fix FileNotFoundError: Verify the file path is correct and the file exists at: {self.filepath}. Check file permissions."
                )
            if "ImportError" in runtime_errors or "ModuleNotFoundError" in runtime_errors:
                 suggestions.append("🔹 Fix ImportError: Ensure required libraries are installed (pip install library_name) and that import paths are correct.")
            if "SyntaxError" in runtime_errors:
                 suggestions.append("🔹 Fix SyntaxError: Review the indicated line for grammatical errors in the code structure (e.g., missing colons, unmatched parentheses).")
            if "IndentationError" in runtime_errors:
                 suggestions.append("🔹 Fix IndentationError: Ensure consistent and correct indentation (spaces or tabs, but not both) for code blocks in Python.")
            if "timed out" in runtime_errors:
                 suggestions.append("🔹 Address Timeout: The script might be in an infinite loop or performing a very long computation. Review loops and complex algorithms.")
            if "can't multiply sequence by non-int of type 'float'" in runtime_errors:
                 suggestions.append("🔹 Fix TypeError: The can't multiply sequence by non-int of type 'float' error usually means you're trying to perform arithmetic with a list or other sequence type and a number. Ensure you are using numeric types where arithmetic is expected.")
        else:
             suggestions.append("🔹 Review the runtime error messages for specific issues.")

        if not suggestions and isinstance(runtime_errors, str) and "No obvious runtime errors found" in runtime_errors:
             suggestions.append("✅ No specific runtime error suggestions based on basic execution.")
        elif not suggestions and isinstance(runtime_errors, str) and runtime_errors.strip():
             suggestions.append(f"🔹 Review the following runtime output for potential issues:\n{runtime_errors}")
        elif not suggestions:
             suggestions.append("🔹 No specific runtime errors detected during basic execution.")

        return suggestions

    # --- Reporting Methods ---

    def save_updated_code_report(self, results, language):
        """Saves the analysis results to a JSON file."""
        base, ext = os.path.splitext(self.filepath)
        json_path = f"{base}_report.json"
        report_data = {
            "file": self.filepath,
            "language": language,
            "results": results,
            # Include original and fixed code in the report
            "original_code": self.original_code,
            "fixed_code": self.fixed_code
            }
        try:
            with open(json_path, "w", encoding=ENCODING) as f:
                json.dump(report_data, f, indent=4)
            print(f"📂 *Report Saved:* {json_path}")
        except Exception as e:
            logging.error(f"Error saving report: {e}")
            print(f"❌ *Error saving report:* {e}")

    def format_security_report_readable(self, security_results):
        """Formats the security report for human readability."""
        if isinstance(security_results, str):
            return security_results # Return error message directly
        elif isinstance(security_results, dict) and security_results.get('results'):
            issues = security_results['results']
            high_severity = sum(1 for issue in issues if issue['severity'] == 'HIGH')
            medium_severity = sum(1 for issue in issues if issue['severity'] == 'MEDIUM')
            low_severity = sum(1 for issue in issues if issue['severity'] == 'LOW')
            total_issues = len(issues)
            report_str = f"Potential security vulnerabilities detected ({total_issues} total):"
            if high_severity > 0:
                report_str += f" High: {high_severity},"
            if medium_severity > 0:
                report_str += f" Medium: {medium_severity},"
            if low_severity > 0:
                report_str += f" Low: {low_severity}"
            # Remove trailing comma if any
            report_str = report_str.rstrip(',') + "."

            # Optionally, list the issues
            # report_str += "\nDetails:"
            # for issue in issues:
            #     report_str += f"\n  - [{issue['severity']}] {issue['test_name']} at {issue['filename']}:{issue['lineno']}: {issue['issue_text']}"

            return report_str
        else:
            return "✅ No critical security issues detected by Bandit."

    def generate_performance_graphs(self, results):
        """Generates and saves performance graphs."""
        base, ext = os.path.splitext(self.filepath)

        # --- Time Metrics Graph ---
        time_labels = ['Analysis and Fixing', 'Report Generation']
        time_values = [
            results.get('time_analysis_fix', 0), # Default to 0 if N/A
            results.get('time_report_generation', 0) # Default to 0 if N/A
        ]

        # Filter out N/A if any. Assuming if one time is N/A, they all might be.
        if all(isinstance(t, (int, float)) for t in time_values):
            plt.figure(figsize=(8, 5))
            plt.bar(time_labels, time_values, color=['blue', 'green'])
            plt.ylabel('Time (seconds)')
            plt.title('Code Review Performance - Time')
            plt.savefig(f"{base}_time_performance.png")
            plt.close() # Close the plot to free memory
            print(f"📊 *Time performance graph saved:* {base}_time_performance.png")
        else:
            print("⚠ Cannot generate time performance graph: time data not available.")


        # --- RAM Usage Graph ---
        # Collect RAM usage data if available numerically
        ram_labels = []
        ram_values = [] # Storing in bytes initially

        # Find the RAM usage keys that have numerical values
        ram_analysis_fix_key = next((k for k in results if k.startswith('ram_usage_analysis_fix') and isinstance(results[k], (int, float))), None)
        ram_report_generation_key = next((k for k in results if k.startswith('ram_usage_report_generation') and isinstance(results[k], (int, float))), None)

        if ram_analysis_fix_key:
             ram_labels.append('Peak RAM (Analysis/Fixing)')
             ram_values.append(results[ram_analysis_fix_key])
        if ram_report_generation_key:
             ram_labels.append('Peak RAM (Report Generation)')
             ram_values.append(results[ram_report_generation_key])

        # Generate graph only if we have numerical RAM data
        if ram_values:
            # Convert RAM values to MB for the graph title and labels
            # Need to know the original unit based on self.memory_module_used
            if self.memory_module_used == 'resource':
                 # If resource was used, values were in kilobytes. Convert to MB.
                 ram_values_mb = [v / 1024 for v in ram_values]
                 unit = "MB (from resource, KB converted)"
            elif self.memory_module_used == 'psutil':
                 # If psutil was used, values were in bytes. Convert to MB.
                 ram_values_mb = [v / (1024 * 1024) for v in ram_values]
                 unit = "MB (from psutil, bytes converted)"
            else:
                 # Should not reach here if ram_values is not empty and self.memory_module_used is None,
                 # but as a fallback.
                 ram_values_mb = ram_values
                 unit = "Unknown Unit"


            plt.figure(figsize=(8, 5))
            plt.bar(ram_labels, ram_values_mb, color=['purple', 'orange'])
            plt.ylabel(f'RAM Usage ({unit})')
            plt.title('Code Review Performance - RAM Usage')
            # Add the exact MB value on top of each bar
            for i, v in enumerate(ram_values_mb):
                plt.text(i, v + (max(ram_values_mb)*0.02 if ram_values_mb else 0.02) , f"{v:.2f} MB", ha='center')

            plt.savefig(f"{base}_ram_performance.png")
            plt.close() # Close the plot to free memory
            print(f"📊 *RAM usage graph saved:* {base}_ram_performance.png")
        else:
            print("⚠ Cannot generate RAM usage graph: numerical RAM data not available.")


    def print_summary(self, results, language):
        """Prints a summary of the code review results to the console."""
        print(f"\n📌 *Code Review Summary for {language.upper()}*:\n")

        # Print language-specific analysis results
        if language == 'python':
            # Display both original and fixed complexity if fixed code exists and is different
            original_complexity = results.get('complexity_original', 'N/A - Analysis failed.')
            fixed_complexity = results.get('complexity_fixed', 'N/A - Analysis failed.')

            if self.fixed_code and self.original_code != self.fixed_code:
                 print(f"⿡ Code Complexity (Maintainability Index):")
                 print(f"   - Original: {original_complexity}")
                 print(f"   - After Formatting: {fixed_complexity}")
            else:
                 print(f"⿡ Code Complexity (Maintainability Index): {original_complexity}")


            print(f"⿢ Duplicates (Lines): {results.get('duplicates', 'N/A - Analysis failed.')}")
            print(f"⿣ Security Issues (Bandit): {self.format_security_report_readable(results.get('security', 'N/A'))}")
            # Runtime errors are still reported from the original file run
            print(f"⿤ Runtime Errors (Basic Execution): {results.get('runtime_errors', 'N/A')}")
            # Magic numbers are now detected on the potentially fixed code
            print(f"⿥ Magic Numbers Found: {results.get('magic_numbers', 'N/A - Analysis failed.')}")
            print(f"⿦ Type Checking (MyPy): \n{results.get('mypy', 'N/A')}")
            print(f"⿧ Style Checking (Flake8): \n{results.get('flake8', 'N/A')}")
            print(f"⿨ Static Analysis (Pylint): \n{results.get('pylint', 'N/A')}")
            print(f"⿩ Dependency Vulnerabilities (Pip-audit): \n{results.get('pip_audit', 'N/A')}")
        elif language == 'javascript':
            print(f"➡ *JavaScript Analysis (ESLint):*\n{results.get('eslint', 'N/A')}")
            print(f"\n➡ *JavaScript Formatting (Prettier):* {results.get('formatting_status', 'N/A')}")
        elif language == 'html':
            print(f"➡ *HTML Analysis (HTMLHint):*\n{results.get('htmlhint', 'N/A')}")
            print(f"\n➡ *HTML Formatting (Prettier):* {results.get('formatting_status', 'N/A')}")
        elif language == 'java':
            print(f"➡ *Java Style Analysis (Checkstyle):*\n{results.get('checkstyle', 'N/A')}")
            print(f"\n➡ *Java Static Analysis (PMD):*\n{results.get('pmd', 'N/A')}")
            print(f"\n➡ *Java Formatting (Google Java Format):* {results.get('formatting_status', 'N/A')}")
        elif language == 'c':
            print(f"➡ *C Analysis (GCC):*\n{results.get('gcc', 'N/A')}")
            print(f"\n➡ *C Static Analysis (Cppcheck):*\n{results.get('cppcheck', 'N/A')}")
            print(f"\n➡ *C Formatting (clang-format):* {results.get('formatting_status', 'N/A')}")
        elif language == 'cpp':
            print(f"➡ *C++ Analysis (G++):*\n{results.get('gpp', 'N/A')}")
            print(f"\n➡ *C++ Static Analysis (Cppcheck):*\n{results.get('cppcheck', 'N/A')}")
            print(f"\n➡ *C++ Formatting (clang-format):* {results.get('formatting_status', 'N/A')}")
        else:
             print(results.get("basic_analysis", "No analysis performed."))

        # Print performance metrics
        print("\n⏱ *Performance Metrics:*")
        # Format time metrics
        time_analysis_fix = results.get('time_analysis_fix', 'N/A')
        if isinstance(time_analysis_fix, (int, float)):
            print(f"   - Time for Analysis and Fixing: {time_analysis_fix:.4f} seconds")
        else:
            print(f"   - Time for Analysis and Fixing: {time_analysis_fix}")

        time_report_generation = results.get('time_report_generation', 'N/A')
        if isinstance(time_report_generation, (int, float)):
            print(f"   - Time for Report Generation: {time_report_generation:.4f} seconds")
        else:
             print(f"   - Time for Report Generation: {time_report_generation}")

        # Format RAM usage metrics based on which module was used
        # Access the values using the keys that include the module name
        ram_analysis_fix_key = next((k for k in results if k.startswith('ram_usage_analysis_fix')), None)
        ram_report_generation_key = next((k for k in results if k.startswith('ram_usage_report_generation')), None)

        ram_analysis_fix = results.get(ram_analysis_fix_key, 'N/A') if ram_analysis_fix_key else 'N/A (Data key not found)'
        ram_report_generation = results.get(ram_report_generation_key, 'N/A') if ram_report_generation_key else 'N/A (Data key not found)'


        print("   - Peak RAM Usage (Analysis/Fixing): ", end="")
        if isinstance(ram_analysis_fix, (int, float)):
             # Determine the unit based on the module used
             if self.memory_module_used == 'resource':
                 # resource.getrusage often returns in kilobytes
                 print(f"{ram_analysis_fix / 1024:.2f} MB ({self.memory_module_used})")
             elif self.memory_module_used == 'psutil':
                 # psutil.Process().memory_info().rss returns in bytes
                 print(f"{ram_analysis_fix / (1024 * 1024):.2f} MB ({self.memory_module_used})")
             else: # Should not reach here if it's a number, but as a fallback
                  print(f"{ram_analysis_fix} (Unknown unit)")
        else:
            print(ram_analysis_fix) # Print N/A or error message

        print("   - Peak RAM Usage (Report Generation): ", end="")
        if isinstance(ram_report_generation, (int, float)):
             # Determine the unit based on the module used
             if self.memory_module_used == 'resource':
                 # resource.getrusage often returns in kilobytes
                 print(f"{ram_report_generation / 1024:.2f} MB ({self.memory_module_used})")
             elif self.memory_module_used == 'psutil':
                 # psutil.Process().memory_info().rss returns in bytes
                 print(f"{ram_report_generation / (1024 * 1024):.2f} MB ({self.memory_module_used})")
             else: # Should not reach here if it's a number, but as a fallback
                  print(f"{ram_report_generation} (Unknown unit)")
        else:
             print(ram_report_generation) # Print N/A or error message


        # Print code modifications (diff) and fixed code if available
        if self.original_code and self.fixed_code and self.original_code != self.fixed_code:
            print("\n📝 *Code Modifications (Diff):*")
            # Generate and print the diff between original and fixed code
            differ = difflib.Differ()
            diff = differ.compare(self.original_code.splitlines(), self.fixed_code.splitlines())
            print('\n'.join(diff))

            print("\n✨ *Formatted/Fixed Code:*")
            print(self.fixed_code)
        elif self.fixed_code:
             # If only fixed code is available (e.g., for languages formatted in-place)
             print("\n✨ *Formatted Code:*")
             print(self.fixed_code)


        # Print fix suggestions
        if results.get('Fix Suggestions'):
            print("\n🔧 *Suggestions for Fixing Issues:*")
            for suggestion in results["Fix Suggestions"]:
                print(suggestion)

        print("\n🎯 *Code review completed.*\n")


if _name_ == "_main_":
    # Argument parsing for the file path
    parser = argparse.ArgumentParser(description="Automated Code Review System")
    parser.add_argument("filepath", help="Path to the file to review")
    args = parser.parse_args()

    # Create and run the review system
    review_system = CodeReviewSystem(args.filepath)
    review_system.run_review()
