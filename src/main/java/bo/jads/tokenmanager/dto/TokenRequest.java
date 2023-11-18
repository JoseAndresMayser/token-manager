package bo.jads.tokenmanager.dto;

import bo.jads.tokenmanager.enums.ExpirationTimeType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class TokenRequest<Data> {

    private String subject;
    private ExpirationTimeType expirationTimeType;
    private Integer expirationTimeAmount;
    private Data data;

}