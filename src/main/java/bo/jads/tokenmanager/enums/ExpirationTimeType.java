package bo.jads.tokenmanager.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Calendar;

@AllArgsConstructor
@Getter
public enum ExpirationTimeType {

    MINUTE(Calendar.MINUTE),
    HOUR(Calendar.HOUR),
    DAY(Calendar.DAY_OF_MONTH),
    MONTH(Calendar.MONTH),
    YEAR(Calendar.YEAR);

    private final Integer value;

}