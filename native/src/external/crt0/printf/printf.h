/**
 * @author (c) Eyal Rozenberg <eyalroz1@gmx.com>
 *             2021-2023, Haifa, Palestine/Israel
 * @author (c) Marco Paland (info@paland.com)
 *             2014-2019, PALANDesign Hannover, Germany
 *
 * @note Others have made smaller contributions to this file: see the
 * contributors page at https://github.com/eyalroz/printf/graphs/contributors
 * or ask one of the authors.
 *
 * @brief Small stand-alone implementation of the printf family of functions
 * (`(v)printf`, `(v)s(n)printf` etc., geared towards use on embedded systems
 * with a very limited resources.
 *
 * @note the implementations are thread-safe; re-entrant; use no functions from
 * the standard library; and do not dynamically allocate any memory.
 *
 * @license The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef PRINTF_H_
#define PRINTF_H_

#ifdef __cplusplus
# include <cstdarg>
# include <cstddef>
extern "C" {
#else
# include <stdarg.h>
# include <stddef.h>
#endif

#ifdef __GNUC__
# if ((__GNUC__ == 4 && __GNUC_MINOR__>= 4) || __GNUC__ > 4)
#  define ATTR_PRINTF(one_based_format_index, first_arg) \
__attribute__((format(gnu_printf, (one_based_format_index), (first_arg))))
# else
# define ATTR_PRINTF(one_based_format_index, first_arg) \
__attribute__((format(printf, (one_based_format_index), (first_arg))))
# endif
# define ATTR_VPRINTF(one_based_format_index) \
ATTR_PRINTF((one_based_format_index), 0)
#else
# define ATTR_PRINTF(one_based_format_index, first_arg)
# define ATTR_VPRINTF(one_based_format_index)
#endif

// If you want to include this implementation file directly rather than
// link against it, this will let you control the functions' visibility,
// e.g. make them static so as not to clash with other objects also
// using them.
#ifndef PRINTF_VISIBILITY
#define PRINTF_VISIBILITY
#endif

/**
 * printf/vprintf with user-specified output function
 *
 * An alternative to @ref printf_, in which the output function is specified
 * dynamically (rather than @ref putchar_ being used)
 *
 * @param out An output function which takes one character and a type-erased
 *     additional parameters
 * @param extra_arg The type-erased argument to pass to the output function @p
 *     out with each call
 * @param format A string specifying the format of the output, with %-marked
 *     specifiers of how to interpret additional arguments.
 * @param arg Additional arguments to the function, one for each specifier in
 *     @p format
 * @return The number of characters for which the output f unction was invoked,
 *     not counting the terminating null character
 *
 */
PRINTF_VISIBILITY
int vfctprintf(void (*out)(char c, void* extra_arg), void* extra_arg, const char* format, va_list arg) ATTR_VPRINTF(3);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // PRINTF_H_
