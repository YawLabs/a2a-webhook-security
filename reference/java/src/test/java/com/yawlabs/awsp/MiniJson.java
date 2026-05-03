// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.
//
// Tiny JSON parser used only by the test suite. The user-facing rule for
// the Java port is "no test deps beyond JUnit 5", so we cannot pull in
// Jackson / Gson. The vector file is well-formed and limited in shape:
// objects / arrays / strings / non-fractional numbers / booleans / nulls.

package com.yawlabs.awsp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, no-deps JSON parser sufficient for {@code test-vectors.json}.
 *
 * <p>Output types:
 * <ul>
 *   <li>JSON object -> {@code Map<String, Object>} (LinkedHashMap, preserves order)</li>
 *   <li>JSON array  -> {@code List<Object>}</li>
 *   <li>JSON string -> {@code String}</li>
 *   <li>JSON number -> {@code Long} (integers) or {@code Double} (with decimal/exponent)</li>
 *   <li>JSON true/false -> {@code Boolean}</li>
 *   <li>JSON null -> {@code null}</li>
 * </ul>
 *
 * <p>This is NOT a general-purpose JSON parser. It implements RFC 8259 well
 * enough to handle the test vectors and nothing more. Do not use it outside
 * the test suite.
 */
final class MiniJson {

    private final String src;
    private int pos;

    private MiniJson(String src) {
        this.src = src;
        this.pos = 0;
    }

    /** Parse a complete JSON document from {@code src}. */
    static Object parse(String src) {
        MiniJson p = new MiniJson(src);
        p.skipWs();
        Object value = p.readValue();
        p.skipWs();
        if (p.pos != src.length()) {
            throw new RuntimeException("trailing garbage at offset " + p.pos);
        }
        return value;
    }

    private Object readValue() {
        skipWs();
        if (pos >= src.length()) {
            throw new RuntimeException("unexpected EOF");
        }
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't', 'f' -> readBoolean();
            case 'n' -> readNull();
            case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' -> readNumber();
            default -> throw new RuntimeException("unexpected '" + c + "' at " + pos);
        };
    }

    private Map<String, Object> readObject() {
        expect('{');
        Map<String, Object> obj = new LinkedHashMap<>();
        skipWs();
        if (peek() == '}') {
            pos++;
            return obj;
        }
        while (true) {
            skipWs();
            String key = readString();
            skipWs();
            expect(':');
            Object value = readValue();
            obj.put(key, value);
            skipWs();
            char nx = src.charAt(pos);
            if (nx == ',') {
                pos++;
                continue;
            }
            if (nx == '}') {
                pos++;
                return obj;
            }
            throw new RuntimeException("expected ',' or '}' at " + pos);
        }
    }

    private List<Object> readArray() {
        expect('[');
        List<Object> arr = new ArrayList<>();
        skipWs();
        if (peek() == ']') {
            pos++;
            return arr;
        }
        while (true) {
            Object v = readValue();
            arr.add(v);
            skipWs();
            char nx = src.charAt(pos);
            if (nx == ',') {
                pos++;
                continue;
            }
            if (nx == ']') {
                pos++;
                return arr;
            }
            throw new RuntimeException("expected ',' or ']' at " + pos);
        }
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < src.length()) {
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= src.length()) {
                    throw new RuntimeException("dangling escape at EOF");
                }
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > src.length()) {
                            throw new RuntimeException("bad \\u escape at " + (pos - 2));
                        }
                        int cp = Integer.parseInt(src.substring(pos, pos + 4), 16);
                        sb.append((char) cp);
                        pos += 4;
                    }
                    default -> throw new RuntimeException("bad escape \\" + esc + " at " + (pos - 2));
                }
            } else {
                sb.append(c);
            }
        }
        throw new RuntimeException("unterminated string");
    }

    private Object readNumber() {
        int start = pos;
        if (src.charAt(pos) == '-') pos++;
        while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        boolean isFloat = false;
        if (pos < src.length() && src.charAt(pos) == '.') {
            isFloat = true;
            pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        }
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            isFloat = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
        }
        String slice = src.substring(start, pos);
        if (isFloat) {
            return Double.parseDouble(slice);
        }
        return Long.parseLong(slice);
    }

    private Boolean readBoolean() {
        if (src.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }
        if (src.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }
        throw new RuntimeException("expected boolean at " + pos);
    }

    private Object readNull() {
        if (src.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw new RuntimeException("expected null at " + pos);
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= src.length()) {
            throw new RuntimeException("unexpected EOF");
        }
        return src.charAt(pos);
    }

    private void expect(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) {
            throw new RuntimeException("expected '" + c + "' at " + pos);
        }
        pos++;
    }
}
