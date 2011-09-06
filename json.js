/* Copyright (C) 2011 by Danny Hooper

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

===============================================================================

This is a completely validating JSON parser that makes use of the native JSON
parser if available, and otherwise evals the source string after it has been
validated. It returns null upon failure. Note that if the native parser has
unexpected behavior, then so does this function.

The state of the art in JSON parsing (in Javascript) seems to be centered
around heuristics for detecting malicious inputs, such as parentheses outside
of strings. Such implementations do not truly validate their input, and may be
vulnerable to newly concocted methods of circumvention. They also, in many
cases, fail and throw uncaught exceptions when certain invalid inputs are
provided.

This implementation aims to correctly validate JSON texts by performing the
reductions specified in the JSON grammar until no further reductions are
possible. The reductions are performed by replacing regex matches with reduced
tokens in the string. This is competitively fast since, like most
implementations, the bulk of the time is still spent in the call to eval rather
than in the validation. */

function json_parse(str) {
    // Use the native JSON parser if available
    if (window.JSON && window.JSON.parse)
        try       { return window.JSON.parse(str) }
        catch (x) { return null }

    // Make a copy of the input string to destroy during validation
    var test = str

    // Reduce string literals to string atoms (S)
    test = test.replace(/"([^"\\]|\\["\\\/bfnrt]|\\u\d{4})*"/g, "S")

    // Reduce number literals to generic atoms (A)
    test = test.replace(/(-?[1-9]*\d)(\.\d+)?([eE][+-]?\d+)?/g, "A")

    // Reduce other literals to generic atoms
    test = test.replace(/(true|false|null)/g, "A")

    // Any remaining whitespace is unimportant
    test = test.replace(/\s/g, "")

    // Reduce the inner-most objects and arrays until none are left
    var prev
    do {
        // Remember test so we can tell if changes occurred
        prev = test
    
        // Reduce flat arrays to container atoms (C)
        test = test.replace(/\[([SAC](,[SAC])*)?\]/g, "C")
    
        // Reduce flat objects to container atoms
        test = test.replace(/{(S:[SAC](,S:[SAC])*)?}/g, "C")
    }
    while (prev != test
        && test != "C") // Short circuit if we're already reduced

    // If we reduced successfully, the string matched the JSON grammar, and
    // we can evaluate it safely. Otherwise return null for failure.
    return test == "C" ? eval("("+str+")") : null
}

