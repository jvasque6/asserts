FROM registry.gitlab.com/fluidattacks/asserts/mocks/ftp:weak

ENV FLAVOR hard

EXPOSE 20 21 21000-21100

COPY etc_vsftpd_conf.hard /etc/vsftpd/vsftpd.conf
RUN sed -i -e 's/pam_unix.so nullok/pam_unix.so nullok_secure/g' /etc/pam.d/base-auth && \
    sed -i -e 's/pam_unix.so nullok obscure/pam_unix.so obscure/g' /etc/pam.d/base-password && \
    echo root:yoYeighoohoh1Equ | chpasswd && \
    echo nonpass:yoYeighoohoh1Equ | chpasswd && \
    echo guessed:yoYeighoohoh1Equ | chpasswd

CMD /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
