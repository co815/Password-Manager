package com.example.pm;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.example.pm.exceptions.ErrorResponse;

import java.time.Instant;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex){
        ErrorResponse error_response = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),"INTERNAL SERVER ERROR","Ai facut ceva NEORTODOX cu serverul");
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(error_response);
    }
}