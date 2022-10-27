cmake_minimum_required(VERSION 3.22)

project(teep_armadillo_trial C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SRC host/main.c host/http_client.c host/http_client_cose.c host/sign_verify.c)
set(IETF_PACKAGES ${CMAKE_SOURCE_DIR}/../../../ietf-packages)
set(TARGET_USRLIB ${CMAKE_SOURCE_DIR}/../../target/usr/lib)

add_executable(${PROJECT_NAME} ${SRC})

target_include_directories(
  ${PROJECT_NAME} PRIVATE
  ${IETF_PACKAGES}/QCBOR/inc
  ${IETF_PACKAGES}/t_cose/inc
  ${IETF_PACKAGES}/libcsuit/inc
  ${IETF_PACKAGES}/libteep/inc
  ${IETF_PACKAGES}/openssl-1.1.1l/include
  host/include
  ta/include
  include)

target_link_libraries(
  ${PROJECT_NAME} PRIVATE
  ${TARGET_USRLIB}/libqcbor.so
  ${TARGET_USRLIB}/libt_cose.so
  ${TARGET_USRLIB}/libcsuit.so
  ${TARGET_USRLIB}/libteep.so
  crypto
  teec
  curl
)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
