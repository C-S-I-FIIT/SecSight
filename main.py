#from app.pages.sigma_rules import show_sigma_rules_page
from app.pages.control_page import show_control_page
from app.pages.attack import show_attack_navigator_page
from app.pages.sigma_new import show_sigma_dashboard
from app.pages.elastic import elastic_page
from app.pages.thehive import thehive_page
import streamlit as st
import streamlit_nested_layout  # Needed for nestet layouts like epxanders in expanders
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader



import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="Security Report Dashboard", layout="wide")


# Make the centered layout wider
# st.markdown("""
#     <style>
#         .block-container {
#             max-width: 1200px;
#             padding-top: 2rem;
#             padding-right: 2rem;
#             padding-left: 2rem;
#             padding-bottom: 3rem;
#         }
#     </style>
# """, unsafe_allow_html=True)

def main():
    #authenticator = auth_module()
    st.session_state['authentication_status'] = True

    if st.session_state.get('authentication_status'):
        #authenticator.logout('Logout', 'sidebar')

        
        tabs = st.tabs(["SIGMA Rules", "ATT&CK & Compliance", "Elastic", "Alerts & Cases", "Control Panel"])
        with tabs[0]:
            try:
            #show_sigma_rules_page()
                show_sigma_dashboard()
            except Exception as e:
                st.error(e)

            #st.write("Coming soon")
        with tabs[1]:
            try:
                show_attack_navigator_page()
            except Exception as e:
                st.error(e)
        with tabs[2]:
            try:
                elastic_page()
            except Exception as e:
                st.error(e)
        with tabs[3]:
            try:
                thehive_page()
            except Exception as e:
                st.error(e)
        with tabs[4]:
            show_control_page()
    elif st.session_state.get('authentication_status') == False:
        st.error("Authentication failed")
    elif st.session_state.get('authentication_status') == None:
        st.warning("Please enter your credentials")
        #authenticator.login()
def auth_module():
    with open('streamlit-auth.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)
        
    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days']
    )
    
    return authenticator

if __name__ == "__main__":
    main()



