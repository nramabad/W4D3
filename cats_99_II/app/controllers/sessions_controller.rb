class SessionsController < ApplicationController

  def new
  end

  def create
    user = User.find_by_credentials(
      params[:user][:username],
      params[:user][:password]
    )
    if user
      login!(user)
      redirect_to user_url(user)
    else
      flash.now[:errors] = ['Invalid Credentials']
      render :new
    end
  end

  def destroy
    if current_user
      @current_user.reset_session_token! #
      @current_user = nil
    end
  end

end
