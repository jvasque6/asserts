FROM registry.gitlab.com/fluidattacks/asserts/mocks/ftp:weak

ENV FLAVOR hard

EXPOSE 20/tcp 21/tcp

COPY etc_vsftpd_conf.hard /etc/vsftpd/vsftpd.conf
RUN sed -i -e 's/pam_unix.so nullok/pam_unix.so nullok_secure/g' /etc/pam.d/base-auth
RUN sed -i -e 's/pam_unix.so nullok obscure/pam_unix.so obscure/g' /etc/pam.d/base-password
RUN echo root:yoYeighoohoh1Equ | chpasswd
RUN echo nonpass:yoYeighoohoh1Equ | chpasswd
RUN echo guessed:yoYeighoohoh1Equ | chpasswd

CMD /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
