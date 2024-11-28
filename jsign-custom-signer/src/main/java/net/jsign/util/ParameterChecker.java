package net.jsign.util;

public class ParameterChecker {

    public boolean checkIfBoolean(String value) {
        return value.equals("true") || value.equals("false") ||
                value.equals("0") || value.equals("1") ||
                value.equals("TRUE") || value.equals("FALSE");
    }

    public boolean checkIfInteger(String value) {
        try {
            Integer.parseInt(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public boolean checkIfStringisEmpty(String[] values) {
        for (String value : values) {
            if (value.isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
